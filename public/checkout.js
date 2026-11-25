'use strict';

const quantityInput = document.querySelector('#checkout-quantity');
const totalOutput = document.querySelector('#checkout-total');
const unitCents = Number(totalOutput.dataset.unitCents);

quantityInput.addEventListener('input', () => {
    const quantity = Number(quantityInput.value);
    const validQuantity = quantityInput.validity.valid && /^[0-9]{1,3}$/.test(quantityInput.value);
    totalOutput.value = validQuantity ? `RM ${(unitCents * quantity / 100).toFixed(2)}` : '—';
});
