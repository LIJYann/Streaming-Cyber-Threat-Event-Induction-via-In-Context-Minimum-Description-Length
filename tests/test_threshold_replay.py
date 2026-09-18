import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from threshold_sweep import replay


def trace():
    return [
        dict(id='a', label='UNSEEN_EVENT', target=None, n_candidates=0,
             best_delta_r_bits=0, best_similarity=0),
        dict(id='b', label='RELATED_EVENT', target=None, n_candidates=1,
             best_delta_r_bits=.07, best_similarity=.2),
    ]


def test_legacy_promotion_fails_closed():
    with pytest.raises(ValueError, match='missing earlier best candidate'):
        replay(trace(), .05, .02)


def test_recorded_candidate_supports_promotion():
    rows=trace()
    rows[1]['best_candidate_id']='a'
    assert replay(rows,.05,.02)[1] == dict(id='b',label='SAME_EVENT',target='a')


def test_no_candidate_is_never_same_even_at_zero_threshold():
    assert replay(trace()[:1],0,0)[0]['label']=='UNSEEN_EVENT'
