import azure.functions as func

app = func.FunctionApp()


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def nsg_scan(timer: func.TimerRequest) -> None:
    """Placeholder - fleshed out in Task 4."""
