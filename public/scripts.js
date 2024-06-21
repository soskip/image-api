document.addEventListener("DOMContentLoaded", function() {
    fetch('/api/usage')
        .then(response => response.json())
        .then(data => {
            const config = {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'API Calls (Last 24h)',
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        data: data.data,
                    }]
                },
                options: {}
            };
            new Chart(document.getElementById('apiUsageChart'), config);
        });
});
