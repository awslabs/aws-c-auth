import Builder
import json
import os
import re
import subprocess
import sys


class AWSCAuthTest(Builder.Action):

    def _get_secret(self, env, secret_id):
        """get string from secretsmanager"""

        # NOTE: using AWS CLI instead of boto3 because we know CLI is already
        # installed wherever builder is run. Once upon a time we tried using
        # boto3 by installing it while the builder was running but this didn't
        # work in some rare scenarios.

        cmd = ['aws', '--region', 'us-east-1', 'secretsmanager', 'get-secret-value',
               '--secret-id', secret_id]
        # NOTE: print command args, but use "quiet" mode so that output isn't printed.
        # we don't want secrets leaked to the build log
        print('>', subprocess.list2cmdline(cmd))
        result = env.shell.exec(*cmd, check=True, quiet=True)
        secret_value = json.loads(result.output)
        return secret_value['SecretString']

    def run(self, env):
        env.shell.setenv("AWS_TESTING_COGNITO_IDENTITY", self._get_secret(env, "aws-c-auth-testing/cognito-identity"), quiet=True)

        actions = []

        if os.path.exists('./build/aws-c-auth/'):
            # This is the directory (relative to repo root) that will contain the build when the repo is built directly by the
            # builder
            os.chdir('./build/aws-c-auth/')
        elif os.path.exists('../../aws-c-auth'):
            # This is the directory (relative to repo root) that will contain the build when the repo is built as an upstream
            # consumer
            os.chdir('../../aws-c-auth')

        actions.append(['ctest', '--output-on-failure'])

        return Builder.Script(actions, name='aws-c-auth-test')
