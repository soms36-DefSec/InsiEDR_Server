from datetime import date

from server.storage.repositories.model_repo import ModelReviewRepository


class Cursor:
    rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, query, params):
        assert query.count("%s") == len(params)

    def fetchall(self):
        return []


class Connection:
    def __init__(self):
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def cursor(self):
        return Cursor()

    def commit(self):
        self.committed = True


class Storage:
    def __init__(self):
        self.last = None

    def connection(self):
        self.last = Connection()
        return self.last


def test_score_and_queue_queries_bind_all_values():
    storage = Storage()
    repo = ModelReviewRepository(storage)
    repo.save_endpoint_score(dict(agent_id="AGENT-01", hostname="A",
        review_date=date(2026, 10, 20), observation_complete=False,
        selection_status="abstain_missing_sensors"))
    assert storage.last.committed
    repo.save_review_queue(date(2026, 10, 20), [dict(agent_id="AGENT-01", hostname="A",
        pair_threat_score=.7, primary_hypothesis="DATA_HOARDING",
        scenario_probabilities={"DATA_HOARDING": .8}, evidence_dates=[],
        model_version="Model V3")])
    assert storage.last.committed
