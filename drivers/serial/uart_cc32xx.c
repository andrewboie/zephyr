/*
 * Copyright (c) 2016-2017, Texas Instruments Incorporated
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT ti_cc32xx_uart

#include <kernel.h>
#include <arch/cpu.h>
#include <drivers/uart.h>

/* Driverlib includes */
#include <inc/hw_types.h>
#include <driverlib/rom.h>
#include <driverlib/rom_map.h>
#include <driverlib/prcm.h>
#include <driverlib/uart.h>

struct uart_cc32xx_dev_data_t {
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	uart_irq_callback_user_data_t cb; /**< Callback function pointer */
	void *cb_data; /**< Callback function arg */
#endif /* CONFIG_UART_INTERRUPT_DRIVEN */
};

#define DEV_CFG(dev) \
	((const struct uart_device_config * const)(dev)->config_info)
#define DEV_DATA(dev) \
	((struct uart_cc32xx_dev_data_t * const)(dev)->driver_data)

#define PRIME_CHAR '\r'

/* Forward decls: */
DEVICE_DECLARE(uart_cc32xx_0);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cc32xx_isr(void *arg);
#endif

static const struct uart_device_config uart_cc32xx_dev_cfg_0 = {
	DEVICE_MMIO_ROM_INIT(0),
	.sys_clk_freq = DT_INST_PROP_BY_PHANDLE(0, clocks, clock_frequency)
};

static struct uart_cc32xx_dev_data_t uart_cc32xx_dev_data_0 = {
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.cb = NULL,
#endif
};

/*
 *  CC32XX UART has a configurable FIFO length, from 1 to 8 characters.
 *  However, the Zephyr console driver, and the Zephyr uart sample test, assume
 *  a RX FIFO depth of one: meaning, one interrupt == one character received.
 *  Keeping with this assumption, this driver leaves the FIFOs disabled,
 *  and at depth 1.
 */
static int uart_cc32xx_init(struct device *dev)
{
	MAP_PRCMPeripheralReset(PRCM_UARTA0);

	/* This also calls MAP_UARTEnable() to enable the FIFOs: */
	MAP_UARTConfigSetExpClk(DEVICE_MMIO_GET(dev),
				MAP_PRCMPeripheralClockGet(PRCM_UARTA0),
				DT_INST_PROP(0, current_speed),
				(UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE
				 | UART_CONFIG_PAR_NONE));
	MAP_UARTFlowControlSet(DEVICE_MMIO_GET(dev),
			       UART_FLOWCONTROL_NONE);
	/* Re-disable the FIFOs: */
	MAP_UARTFIFODisable(DEVICE_MMIO_GET(dev));

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	/* Clear any pending UART RX interrupts: */
	MAP_UARTIntClear(DEVICE_MMIO_GET(dev), UART_INT_RX);

	IRQ_CONNECT(DT_INST_IRQN(0),
		    DT_INST_IRQ(0, priority),
		    uart_cc32xx_isr, DEVICE_GET(uart_cc32xx_0),
		    0);
	irq_enable(DT_INST_IRQN(0));

	/* Fill the tx fifo, so Zephyr console & shell subsystems get "primed"
	 * with first tx fifo empty interrupt when they first call
	 * uart_irq_tx_enable().
	 */
	MAP_UARTCharPutNonBlocking(DEVICE_MMIO_GET(dev), PRIME_CHAR);
#endif
	return 0;
}

static int uart_cc32xx_poll_in(struct device *dev, unsigned char *c)
{
	if (MAP_UARTCharsAvail(DEVICE_MMIO_GET(dev))) {
		*c = MAP_UARTCharGetNonBlocking(DEVICE_MMIO_GET(dev));
	} else {
		return (-1);
	}
	return 0;
}

static void uart_cc32xx_poll_out(struct device *dev, unsigned char c)
{
	MAP_UARTCharPut(DEVICE_MMIO_GET(dev), c);
}

static int uart_cc32xx_err_check(struct device *dev)
{
	unsigned long cc32xx_errs = 0L;
	unsigned int z_err = 0U;

	cc32xx_errs = MAP_UARTRxErrorGet(DEVICE_MMIO_GET(dev));

	/* Map cc32xx SDK uart.h defines to zephyr uart.h defines */
	z_err = ((cc32xx_errs & UART_RXERROR_OVERRUN) ?
		  UART_ERROR_OVERRUN : 0) |
		((cc32xx_errs & UART_RXERROR_BREAK) ? UART_BREAK : 0) |
		((cc32xx_errs & UART_RXERROR_PARITY) ? UART_ERROR_PARITY : 0) |
		((cc32xx_errs & UART_RXERROR_FRAMING) ? UART_ERROR_FRAMING : 0);

	MAP_UARTRxErrorClear(DEVICE_MMIO_GET(dev));

	return (int)z_err;
}

#ifdef CONFIG_UART_INTERRUPT_DRIVEN

static int uart_cc32xx_fifo_fill(struct device *dev, const uint8_t *tx_data,
				 int size)
{
	unsigned int num_tx = 0U;

	while ((size - num_tx) > 0) {
		/* Send a character */
		if (MAP_UARTCharPutNonBlocking(DEVICE_MMIO_GET(dev),
					       tx_data[num_tx])) {
			num_tx++;
		} else {
			break;
		}
	}

	return (int)num_tx;
}

static int uart_cc32xx_fifo_read(struct device *dev, uint8_t *rx_data,
				 const int size)
{
	unsigned int num_rx = 0U;

	while (((size - num_rx) > 0) &&
		MAP_UARTCharsAvail(DEVICE_MMIO_GET(dev))) {

		/* Receive a character */
		rx_data[num_rx++] =
			MAP_UARTCharGetNonBlocking(DEVICE_MMIO_GET(dev));
	}

	return num_rx;
}

static void uart_cc32xx_irq_tx_enable(struct device *dev)
{
	MAP_UARTIntEnable(DEVICE_MMIO_GET(dev), UART_INT_TX);
}

static void uart_cc32xx_irq_tx_disable(struct device *dev)
{
	MAP_UARTIntDisable(DEVICE_MMIO_GET(dev), UART_INT_TX);
}

static int uart_cc32xx_irq_tx_ready(struct device *dev)
{
	unsigned int int_status;

	int_status = MAP_UARTIntStatus(DEVICE_MMIO_GET(dev), 1);

	return (int_status & UART_INT_TX);
}

static void uart_cc32xx_irq_rx_enable(struct device *dev)
{
	/* FIFOs are left disabled from reset, so UART_INT_RT flag not used. */
	MAP_UARTIntEnable(DEVICE_MMIO_GET(dev), UART_INT_RX);
}

static void uart_cc32xx_irq_rx_disable(struct device *dev)
{
	MAP_UARTIntDisable(DEVICE_MMIO_GET(dev), UART_INT_RX);
}

static int uart_cc32xx_irq_tx_complete(struct device *dev)
{
	return (!MAP_UARTBusy(DEVICE_MMIO_GET(dev)));
}

static int uart_cc32xx_irq_rx_ready(struct device *dev)
{
	unsigned int int_status;

	int_status = MAP_UARTIntStatus(DEVICE_MMIO_GET(dev), 1);

	return (int_status & UART_INT_RX);
}

static void uart_cc32xx_irq_err_enable(struct device *dev)
{
	/* Not yet used in zephyr */
}

static void uart_cc32xx_irq_err_disable(struct device *dev)
{
	/* Not yet used in zephyr */
}

static int uart_cc32xx_irq_is_pending(struct device *dev)
{
	unsigned int int_status;

	int_status = MAP_UARTIntStatus(DEVICE_MMIO_GET(dev), 1);

	return (int_status & (UART_INT_TX | UART_INT_RX));
}

static int uart_cc32xx_irq_update(struct device *dev)
{
	return 1;
}

static void uart_cc32xx_irq_callback_set(struct device *dev,
					 uart_irq_callback_user_data_t cb,
					 void *cb_data)
{
	struct uart_cc32xx_dev_data_t * const dev_data = DEV_DATA(dev);

	dev_data->cb = cb;
	dev_data->cb_data = cb_data;
}

/**
 * @brief Interrupt service routine.
 *
 * This simply calls the callback function, if one exists.
 *
 * Note: CC32XX UART Tx interrupts when ready to send; Rx interrupts when char
 * received.
 *
 * @param arg Argument to ISR.
 *
 * @return N/A
 */
static void uart_cc32xx_isr(void *arg)
{
	struct device *dev = arg;
	struct uart_cc32xx_dev_data_t * const dev_data = DEV_DATA(dev);

	unsigned long intStatus = MAP_UARTIntStatus(DEVICE_MMIO_GET(dev),
						    1);

	if (dev_data->cb) {
		dev_data->cb(dev_data->cb_data);
	}
	/*
	 * RX/TX interrupt should have been implicitly cleared by Zephyr UART
	 * clients calling uart_fifo_read() or uart_fifo_write().
	 * Still, clear any error interrupts here, as they're not yet handled.
	 */
	MAP_UARTIntClear(DEVICE_MMIO_GET(dev),
			 intStatus & ~(UART_INT_RX | UART_INT_TX));
}
#endif /* CONFIG_UART_INTERRUPT_DRIVEN */

static const struct uart_driver_api uart_cc32xx_driver_api = {
	.poll_in = uart_cc32xx_poll_in,
	.poll_out = uart_cc32xx_poll_out,
	.err_check = uart_cc32xx_err_check,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.fifo_fill	  = uart_cc32xx_fifo_fill,
	.fifo_read	  = uart_cc32xx_fifo_read,
	.irq_tx_enable	  = uart_cc32xx_irq_tx_enable,
	.irq_tx_disable	  = uart_cc32xx_irq_tx_disable,
	.irq_tx_ready	  = uart_cc32xx_irq_tx_ready,
	.irq_rx_enable	  = uart_cc32xx_irq_rx_enable,
	.irq_rx_disable	  = uart_cc32xx_irq_rx_disable,
	.irq_tx_complete  = uart_cc32xx_irq_tx_complete,
	.irq_rx_ready	  = uart_cc32xx_irq_rx_ready,
	.irq_err_enable	  = uart_cc32xx_irq_err_enable,
	.irq_err_disable  = uart_cc32xx_irq_err_disable,
	.irq_is_pending	  = uart_cc32xx_irq_is_pending,
	.irq_update	  = uart_cc32xx_irq_update,
	.irq_callback_set = uart_cc32xx_irq_callback_set,
#endif /* CONFIG_UART_INTERRUPT_DRIVEN */
};

DEVICE_AND_API_INIT(uart_cc32xx_0, DT_INST_LABEL(0),
		    uart_cc32xx_init, &uart_cc32xx_dev_data_0,
		    &uart_cc32xx_dev_cfg_0,
		    PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    (void *)&uart_cc32xx_driver_api);
