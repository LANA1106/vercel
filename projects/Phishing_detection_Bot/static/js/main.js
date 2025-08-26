// Utility functions
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    element.innerHTML = `
        <div class="p-4 rounded-xl bg-white/10">
            <div class="flex items-center justify-center">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-white"></div>
                <span class="ml-3">Analyzing...</span>
            </div>
        </div>
    `;
    element.classList.remove('hidden');
}

function showResult(elementId, result, type) {
    const element = document.getElementById(elementId);
    element.innerHTML = `
        <div class="analysis-result ${type}">
            <h3>${result.title}</h3>
            <p>${result.message}</p>
            <div class="details">${result.details}</div>
            <div class="feedback-section">
                <p>Was this analysis helpful?</p>
                <div class="feedback-buttons">
                    <button onclick="provideFeedback('${type}', ${result.risk_score}, 'high')" class="btn btn-danger">Too Risky</button>
                    <button onclick="provideFeedback('${type}', ${result.risk_score}, 'medium')" class="btn btn-warning">Moderate Risk</button>
                    <button onclick="provideFeedback('${type}', ${result.risk_score}, 'low')" class="btn btn-success">Safe</button>
                </div>
            </div>
        </div>
    `;
}

function getRiskIcon(riskLevel) {
    switch(riskLevel.toLowerCase()) {
        case 'minimal': return '✅';
        case 'low': return '⚠️';
        case 'medium': return '🔶';
        case 'high': return '🚨';
        default: return '❓';
    }
}

function getRiskColor(riskLevel) {
    switch(riskLevel.toLowerCase()) {
        case 'minimal': return '#10b981';
        case 'low': return '#f59e0b';
        case 'medium': return '#f97316';
        case 'high': return '#ef4444';
        default: return '#6b7280';
    }
}

function getRiskBarColor(riskLevel) {
    switch(riskLevel?.toLowerCase()) {
        case 'minimal': return 'green-500';
        case 'low': return 'yellow-500';
        case 'medium': return 'orange-500';
        case 'high': return 'red-500';
        default: return 'gray-500';
    }
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    element.innerHTML = `
        <div class="p-4 rounded-xl bg-red-500/20 border border-red-500/50">
            <p class="text-red-200">${message}</p>
        </div>
    `;
    element.classList.remove('hidden');
}

// Analysis functions
async function analyzeUrl() {
    const urlInput = document.getElementById('urlInput');
    const urlResult = document.getElementById('urlResult');
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('urlResult', 'Please enter a URL to analyze');
        return;
    }
    
    showLoading('urlResult');
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                content: url,
                type: 'url'
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Create result HTML
            const resultHtml = `
                <div class="p-4 rounded-xl ${getResultClass(result.type)}">
                    <h4 class="text-lg font-semibold mb-2">${result.title}</h4>
                    <p class="mb-2">${result.message}</p>
                    <div class="mt-2">
                        <p class="text-sm">${result.reason}</p>
                    </div>
                </div>
            `;
            
            urlResult.innerHTML = resultHtml;
            urlResult.classList.remove('hidden');
        } else {
            showError('urlResult', result.error || 'Failed to analyze URL');
        }
    } catch (error) {
        showError('urlResult', 'Error analyzing URL: ' + error.message);
    }
}

async function analyzeMessage() {
    const messageInput = document.getElementById('messageInput');
    const messageResult = document.getElementById('messageResult');
    const message = messageInput.value.trim();
    
    if (!message) {
        showError('messageResult', 'Please enter a message to analyze');
        return;
    }
    
    showLoading('messageResult');
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                content: message,
                type: 'message'
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Create result HTML
            let detailsHtml = '';
            
            // Add text and URL scores
            detailsHtml += `
                <div class="mb-3">
                    <p class="text-sm">Text Analysis Score: ${result.details.text_score}/100</p>
                    <p class="text-sm">URL Analysis Score: ${result.details.url_score}/100</p>
                </div>
            `;
            
            // Add detected patterns if any
            if (result.details.patterns && result.details.patterns.length > 0) {
                detailsHtml += `
                    <div class="mb-3">
                        <p class="font-medium mb-1">Detected Patterns:</p>
                        <ul class="list-disc list-inside text-sm">
                            ${result.details.patterns.map(pattern => `<li>${pattern}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Add suspicious URLs if any
            if (result.details.suspicious_urls && result.details.suspicious_urls.length > 0) {
                detailsHtml += `
                    <div class="mb-3">
                        <p class="font-medium mb-1">Suspicious URLs:</p>
                        <ul class="list-disc list-inside text-sm">
                            ${result.details.suspicious_urls.map(url => `<li>${url}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            const resultHtml = `
                <div class="p-4 rounded-xl ${getResultClass(result.type)}">
                    <h4 class="text-lg font-semibold mb-2">${result.title}</h4>
                    <p class="mb-2">${result.message}</p>
                    <div class="mt-2">
                        ${detailsHtml}
                    </div>
                </div>
            `;
            
            messageResult.innerHTML = resultHtml;
            messageResult.classList.remove('hidden');
        } else {
            showError('messageResult', result.error || 'Failed to analyze message');
        }
    } catch (error) {
        showError('messageResult', 'Error analyzing message: ' + error.message);
    }
}

function getResultClass(type) {
    switch (type) {
        case 'success':
            return 'bg-green-500/20 border border-green-500/50';
        case 'warning':
            return 'bg-yellow-500/20 border border-yellow-500/50';
        case 'danger':
            return 'bg-red-500/20 border border-red-500/50';
        default:
            return 'bg-white/10 border border-white/20';
    }
}

// Feedback functions
async function provideFeedback(analysisType, originalRiskScore, feedbackLevel) {
    const riskScoreMap = {
        'high': 80,
        'medium': 50,
        'low': 20
    };
    
    const userFeedback = riskScoreMap[feedbackLevel];
    const content = analysisType === 'url' 
        ? document.getElementById('urlInput').value
        : document.getElementById('messageInput').value;
    
    try {
        const response = await fetch('/api/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                type: analysisType,
                content: content,
                feedback: userFeedback,
                original_risk_score: originalRiskScore
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Show feedback confirmation
            const feedbackSection = document.querySelector('.feedback-section');
            feedbackSection.innerHTML = '<p class="success">Thank you for your feedback! The system has learned from your input.</p>';
            
            // Update learning stats
            updateLearningStats();
        } else {
            console.error('Failed to process feedback:', result.error);
        }
    } catch (error) {
        console.error('Error providing feedback:', error);
    }
}

// Learning stats functions
async function updateLearningStats() {
    try {
        const response = await fetch('/api/learning/stats');
        const stats = await response.json();
        
        if (response.ok) {
            // Update stats display
            const statsElement = document.getElementById('learningStats');
            if (statsElement) {
                statsElement.innerHTML = `
                    <div class="stats-container">
                        <h3>Learning System Statistics</h3>
                        <div class="stats-grid">
                            <div class="stat-item">
                                <span class="stat-label">URL Patterns:</span>
                                <span class="stat-value">${stats.url_patterns}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Message Patterns:</span>
                                <span class="stat-value">${stats.message_patterns}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Domain Patterns:</span>
                                <span class="stat-value">${stats.domain_patterns}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Feedback Entries:</span>
                                <span class="stat-value">${stats.feedback_entries}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Avg URL Risk:</span>
                                <span class="stat-value">${stats.average_url_risk.toFixed(1)}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Avg Message Risk:</span>
                                <span class="stat-value">${stats.average_message_risk.toFixed(1)}</span>
                            </div>
                        </div>
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error updating learning stats:', error);
    }
}

// Chat functions
async function sendMessage() {
    const messageInput = document.getElementById('chatInput');
    const message = messageInput.value.trim();
    
    if (!message) return;
    
    // Add user message to chat
    addMessageToChat(message, 'user');
    messageInput.value = '';
    
    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            addMessageToChat(data.response, 'bot');
        } else {
            addMessageToChat('Error: ' + (data.error || 'Failed to get response'), 'error');
        }
    } catch (error) {
        addMessageToChat('Error: ' + error.message, 'error');
    }
}

function addMessageToChat(message, type) {
    const chatMessages = document.getElementById('chatMessages');
    const messageElement = document.createElement('div');
    messageElement.className = `chat-message ${type}`;
    messageElement.textContent = message;
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Initialize learning stats
    updateLearningStats();
    
    // Set up chat input enter key handler
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
}); 