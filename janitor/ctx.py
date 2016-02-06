import time

from janitor.output import FSOutput, MetricsOutput, CloudWatchLogOutput


class ExecutionContext(object):
    """Policy Execution Context."""
    
    def __init__(self, session_factory, policy, options):
        self.policy = policy
        self.options = options
        self.session_factory = session_factory
        self.cloudwatch_logs = None
        self.start_time = None
        
        metrics_enabled = getattr(options, 'metrics_enabled', None)
        factory = MetricsOutput.select(metrics_enabled)
        self.metrics = factory(self)

        output_dir = getattr(options, 'output_dir', '')
        factory = FSOutput.select(output_dir)
            
        self.output_path = factory.join(output_dir, policy.name)
        self.output = factory(self)

        if options.log_group:
            self.cloudwatch_logs = CloudWatchLogOutput(self)

    @property
    def log_dir(self):
        return self.output.root_dir

    def __enter__(self):
        self.output.__enter__()
        if self.cloudwatch_logs:
            self.cloudwatch_logs.__enter__()
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        self.metrics.flush()
        if self.cloudwatch_logs:
            self.cloudwatch_logs.__exit__(exc_type, exc_value, exc_traceback)
        self.output.__exit__(exc_type, exc_value, exc_traceback)

            
