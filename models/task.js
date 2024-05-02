const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['task', 'section'],
        required: true
    },
    title: {
        type: String,
        required: true
    },
    notes: String,
    completed: {
        type: Boolean,
        default: false
    },
    dueDate: {
        type: Date,
        default: null
    },
    priority: {
        type: Number,
        enum: [0, 1, 2],
        default: 0
    },
    tags: [String],
    order: {
        type: Number,
        required: true
    }
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
