package queue

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"github.com/streadway/amqp"
)

type AMQPPublisher struct {
	url    string
	log    *logging.Logger
	conn   *amqp.Connection
	ch     *amqp.Channel
	mu     sync.Mutex
	closed bool
}

func NewPublisher(url string, log *logging.Logger) *AMQPPublisher {
	p := &AMQPPublisher{
		url: url,
		log: log,
	}
	go p.connectLoop()
	return p
}

func (p *AMQPPublisher) connectLoop() {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		p.log.Info("Connecting to RabbitMQ server...", map[string]interface{}{"url": p.url})
		conn, err := amqp.Dial(p.url)
		if err != nil {
			p.log.Error("RabbitMQ connection failed, retrying in 5 seconds", err, nil)
			time.Sleep(5 * time.Second)
			continue
		}

		ch, err := conn.Channel()
		if err != nil {
			_ = conn.Close()
			p.log.Error("Failed to open RabbitMQ channel, retrying in 5 seconds", err, nil)
			time.Sleep(5 * time.Second)
			continue
		}

		// Declare durable task queue
		_, err = ch.QueueDeclare(
			"fleet_tasks", // name
			true,          // durable
			false,         // delete when unused
			false,         // exclusive
			false,         // no-wait
			nil,           // arguments
		)
		if err != nil {
			_ = ch.Close()
			_ = conn.Close()
			p.log.Error("Failed to declare queue, retrying in 5 seconds", err, nil)
			time.Sleep(5 * time.Second)
			continue
		}

		p.mu.Lock()
		p.conn = conn
		p.ch = ch
		p.mu.Unlock()

		p.log.Info("Connected to RabbitMQ and 'fleet_tasks' queue initialized successfully", nil)

		// Monitor channel close and reconnect
		closeChan := conn.NotifyClose(make(chan *amqp.Error))
		errClose := <-closeChan

		reason := "unknown"
		if errClose != nil {
			reason = errClose.Error()
		}
		p.log.Info("RabbitMQ connection lost, starting reconnect loop...", map[string]interface{}{"reason": reason})

		p.mu.Lock()
		p.conn = nil
		p.ch = nil
		p.mu.Unlock()
	}
}

func (p *AMQPPublisher) PublishTask(task *admiral.FleetTask) error {
	p.mu.Lock()
	ch := p.ch
	p.mu.Unlock()

	body, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}

	if ch == nil {
		return fmt.Errorf("rabbitmq disconnected: task %s was not published", task.TaskID)
	}

	err = ch.Publish(
		"",            // exchange
		"fleet_tasks", // routing key
		false,         // mandatory
		false,         // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         body,
		},
	)
	if err != nil {
		return fmt.Errorf("publish message: %w", err)
	}

	p.log.Info("Task published successfully to RabbitMQ", map[string]interface{}{"task_id": task.TaskID})
	return nil
}

func (p *AMQPPublisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.ch != nil {
		_ = p.ch.Close()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
}
