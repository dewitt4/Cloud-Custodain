import time

from janitor.output import DirectoryOutput, MetricsOutput


class ExecutionContext(object):

    def __init__(self, session_factory, policy, options):
        self.policy = policy
        self.options = options
        self.session_factory = session_factory
        self.metrics = MetricsOutput(self)

        factory = DirectoryOutput.select(options.output_dir)
        self.output_path = factory.join(options.output_dir, policy.name)
        self.output = factory(self)
        self.start_time = None

    @property
    def log_dir(self):
        return self.output.root_dir

    def __enter__(self):
        self.output.__enter__()
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        self.output.__exit__(exc_type, exc_value, exc_traceback)
        self.metrics.put_metric(
            'ExecutionTime',
            time.time()-self.start_time)
