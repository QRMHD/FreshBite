'use strict';

const statusText = document.querySelector('.order .intro');
const steps = document.querySelectorAll('.timeline li');

async function updateStatus() {
    try {
        const response = await fetch(location.pathname + '/status', {
            cache: 'no-store',
            signal: AbortSignal.timeout(10_000),
        });
        if (response.status === 401) {
            location.replace('/login');
            return;
        }
        if (response.status === 404) {
            location.replace('/orders');
            return;
        }
        if (response.ok) {
            const { label, stage } = await response.json();
            if (statusText.textContent !== label) statusText.textContent = label;
            steps.forEach((step, index) => step.classList.toggle('done', index <= stage));
        }
    } catch {
        // Keep the last known status and retry on the next poll.
    }
    setTimeout(updateStatus, 4000);
}

setTimeout(updateStatus, 4000);
