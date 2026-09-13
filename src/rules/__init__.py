from src.rules.eval_rule import check_eval
from src.rules.secret_rule import check_hardcoded_secret
from src.rules.subprocess_rule import check_dangerous_subprocess
from src.rules.crypto_rule import check_weak_crypto
from src.rules.pickle_rule import check_insecure_pickle
from src.rules.sql_rule import check_sql_injection
from src.rules.path_rule import check_path_traversal
from src.rules.command_rule import check_command_injection


SECURITY_RULES = [
    check_eval,
    check_hardcoded_secret,
    check_dangerous_subprocess,
    check_weak_crypto,
    check_insecure_pickle,
    check_sql_injection,
    check_path_traversal,
    check_command_injection,
]