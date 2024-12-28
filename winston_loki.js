const express = require('express');
const winston = require('winston');
const LokiTransport = require('winston-loki');

const app = express();

// Custom formatter to avoid adding extra fields
const customFormatter = winston.format((info) => {
  delete info.level; // Remove the level field
  info.message = info.message; // Keep only the logging message
  info.timestamp = info.timestamp; // Keep the timestamp
  return info; // Return the modified log info object
});

// Create logger
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(), // Add timestamp to logs
    customFormatter(), // Apply custom formatter
    winston.format.json() // Serialize in JSON format
  ),
  transports: [
    new winston.transports.Console(),
    new LokiTransport({
      host: 'http://localhost:3100',
      labels: { job: 'node-app12', type: 'metrics' },
    }),
  ],
});

let count = 1;

// Function to generate realistic CPU and memory usage in a 10-minute interval
const generateRandomMetrics = () => {
  const currentTime = Date.now() % 600000; // Time within a 10-minute interval (in milliseconds)

  // Simulating CPU usage with a sinusoidal pattern for smooth up-and-down motion
  const cpuUsage = (50 + 30 * Math.sin((2 * Math.PI * currentTime) / 600000)).toFixed(2); // Range: ~20 to ~80

  // Simulating memory usage with a different sinusoidal pattern to avoid perfect sync
  const memoryUsage = (40 + 20 * Math.sin((2 * Math.PI * currentTime) / 600000 + Math.PI / 4)).toFixed(2); // Range: ~20 to ~60

  return {
    cpu: cpuUsage.toString(), // String format
    memory: memoryUsage.toString(), // String format
  };
};

// Function to collect and log metrics
const collectMetrics = async () => {
  try {
    const metrics = generateRandomMetrics();

    // Log CPU Usage
    logger.info(`{"CPU Usage":"${metrics.cpu}"}`);

    // Log Memory Usage
    logger.info(`{"Memory Usage":"${metrics.memory}"}`);

    console.log('Log generated', count++);
  } catch (error) {
    console.error('Error collecting metrics:', error);
  }
};
