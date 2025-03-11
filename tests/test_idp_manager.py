import pytest

from bento_lib.auth.permissions import P_QUERY_DATA
from fastapi.testclient import TestClient

from bento_authorization_service.config import get_config
from bento_authorization_service.db import Database
from bento_authorization_service.idp_manager import BaseIdPManager, IdPManagerBadAlgorithmError, get_idp_manager
from bento_authorization_service.policy_engine.evaluation import evaluate

from . import shared_data as sd


def test_base_idp_manager(idp_manager: BaseIdPManager):
    assert idp_manager.debug  # debug mode in mock IdPManager
    assert idp_manager.initialized  # MockIdPManager comes pre-initialized
    assert idp_manager.get_supported_token_signing_algs() == sd.TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS
    assert idp_manager.get_permitted_token_signing_algs() == sd.TEST_IDP_SUPPORTED_TOKEN_SIGNING_ALGOS - frozenset(
        sd.TEST_DISABLED_TOKEN_SIGNING_ALGOS
    )


def test_get_idp_manager(logger):
    assert isinstance(get_idp_manager(get_config(), logger), BaseIdPManager)


# noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_invalid_token_algo(
    db: Database, idp_manager: BaseIdPManager, logger, test_client: TestClient, db_cleanup
):
    # should throw exception (using HS256)
    with pytest.raises(IdPManagerBadAlgorithmError):
        await evaluate(
            idp_manager,
            db,
            logger,
            sd.make_fresh_david_disabled_alg_encoded(),
            (sd.RESOURCE_PROJECT_1,),
            (P_QUERY_DATA,),
        )
