"""
Setup local mock server for tests
"""

import Builder

import os
import sys
import subprocess
import atexit


class MockServerSetup(Builder.Action):
    """
    Set up this machine for running the mock server test

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping mock server setup because tests disabled for project")
            return

        self.env = env
        python_path = sys.executable

        # set cmake flag so mock server tests are enabled
        env.project.config['cmake_args'].extend(
            ['-DENABLE_AUTH_MOCK_SERVER_TESTS=ON', '-DASSERT_LOCK_HELD=ON'])

        base_dir = os.path.dirname(os.path.realpath(__file__))
        dir = os.path.join(base_dir, "..", "..", "tests", "mock_server")
        process = subprocess.Popen([python_path, "mock_auth_server.py"], cwd=dir)

        @atexit.register
        def close_mock_server():
            process.terminate()
