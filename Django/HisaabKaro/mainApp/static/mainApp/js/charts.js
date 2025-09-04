// Charts functionality for HisaabKaro
let currentChartType = 'home';
let currentChart = null;

function openChartModal(type) {
    currentChartType = type;
    document.getElementById('chartModal').classList.add('show');
    
    // Reset modal state
    document.querySelectorAll('.chart-option').forEach(opt => opt.classList.remove('active'));
    document.getElementById('dateInputs').classList.remove('show');
    document.getElementById('chartContainer').classList.remove('show');
}

function closeChartModal() {
    document.getElementById('chartModal').classList.remove('show');
    if (currentChart) {
        currentChart.destroy();
        currentChart = null;
    }
}

// Chart option selection
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.chart-option').forEach(option => {
        option.addEventListener('click', function() {
            document.querySelectorAll('.chart-option').forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
            
            const type = this.dataset.type;
            const dateInputs = document.getElementById('dateInputs');
            const endDateCol = document.getElementById('endDateCol');
            const startDateLabel = document.querySelector('label[for="startDate"]');
            const startDate = document.getElementById('startDate');
            
            dateInputs.classList.add('show');
            
            if (type === 'day') {
                startDateLabel.textContent = 'Select Date:';
                endDateCol.style.display = 'none';
                startDate.type = 'date';
            } else if (type === 'month') {
                startDateLabel.textContent = 'Select Month:';
                endDateCol.style.display = 'none';
                startDate.type = 'month';
            } else {
                startDateLabel.textContent = 'Start Date:';
                endDateCol.style.display = 'block';
                startDate.type = 'date';
            }
        });
    });

    // Close modal when clicking outside
    const chartModal = document.getElementById('chartModal');
    if (chartModal) {
        chartModal.addEventListener('click', function(e) {
            if (e.target === this) {
                closeChartModal();
            }
        });
    }
});

function generateChart() {
    const selectedOption = document.querySelector('.chart-option.active');
    if (!selectedOption) {
        alert('Please select a time period');
        return;
    }
    
    const type = selectedOption.dataset.type;
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;
    
    if (!startDate) {
        alert('Please select a date');
        return;
    }
    
    if (type === 'range' && !endDate) {
        alert('Please select end date');
        return;
    }
    
    // Prepare data for API call
    const data = {
        period_type: type,
        start_date: startDate,
        end_date: type === 'range' ? endDate : startDate
    };
    
    // API endpoint based on chart type
    let endpoint = '';
    switch(currentChartType) {
        case 'home':
            endpoint = '/charts/home-data/';
            break;
        case 'personal':
            endpoint = '/charts/personal-data/';
            break;
        case 'groups':
            endpoint = '/charts/groups-data/';
            break;
        case 'group_detail':
            // Need to get group ID from page
            const groupId = getGroupIdFromPage();
            if (!groupId) {
                alert('Unable to determine group ID. Please refresh the page and try again.');
                return;
            }
            endpoint = `/charts/group/${groupId}/data/`;
            break;
        default:
            alert('Invalid chart type');
            return;
    }
    
    // Make API call
    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            displayChart(data.data, type, startDate, endDate);
        } else {
            alert('Error generating chart: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error generating chart. Please try again.');
    });
}

function displayChart(data, periodType, startDate, endDate) {
    const ctx = document.getElementById('expenseChart').getContext('2d');
    
    // Destroy existing chart
    if (currentChart) {
        currentChart.destroy();
    }
    
    // Show chart container
    document.getElementById('chartContainer').classList.add('show');
    
    // Check if we have data
    if (!data.labels || data.labels.length === 0) {
        ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
        ctx.fillStyle = '#666';
        ctx.font = '16px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('No data available for the selected period', ctx.canvas.width / 2, ctx.canvas.height / 2);
        
        // Update stats with empty data
        updateChartStats(data, periodType, startDate, endDate);
        return;
    }
    
    // Create new chart
    currentChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF',
                    '#FF9F40',
                    '#FF6384',
                    '#C9CBCF',
                    '#98D8C8',
                    '#F7DC6F'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.raw / total) * 100).toFixed(1);
                            return context.label + ': PKR ' + Math.round(context.raw) + ' (' + percentage + '%)';
                        }
                    }
                }
            }
        }
    });
    
    // Update stats
    updateChartStats(data, periodType, startDate, endDate);
}

function updateChartStats(data, periodType, startDate, endDate) {
    const statsContainer = document.getElementById('chartStats');
    let periodText = '';
    
    if (periodType === 'day') {
        periodText = new Date(startDate).toLocaleDateString();
    } else if (periodType === 'month') {
        periodText = new Date(startDate + '-01').toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
    } else {
        periodText = new Date(startDate).toLocaleDateString() + ' - ' + new Date(endDate).toLocaleDateString();
    }
    
    let statsHTML = `
        <div class="chart-stat">
            <div class="chart-stat-value">PKR ${Math.round(data.total || 0)}</div>
            <div class="chart-stat-label">Total Spending</div>
        </div>
        <div class="chart-stat">
            <div class="chart-stat-value">${(data.labels || []).length}</div>
            <div class="chart-stat-label">Categories</div>
        </div>
        <div class="chart-stat">
            <div class="chart-stat-value">${periodText}</div>
            <div class="chart-stat-label">Period</div>
        </div>
    `;
    
    // Add specific stats based on chart type
    if (currentChartType === 'group_detail' && data.group_total !== undefined) {
        statsHTML += `
            <div class="chart-stat">
                <div class="chart-stat-value">PKR ${Math.round(data.group_total)}</div>
                <div class="chart-stat-label">Group Total</div>
            </div>
            <div class="chart-stat">
                <div class="chart-stat-value">${(data.user_percentage || 0).toFixed(1)}%</div>
                <div class="chart-stat-label">Your Share</div>
            </div>
        `;
    }
    
    statsContainer.innerHTML = statsHTML;
}

// Helper function to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Helper function to get group ID from the current page URL
function getGroupIdFromPage() {
    const path = window.location.pathname;
    const match = path.match(/\/groups\/(\d+)\//);
    return match ? match[1] : null;
}
