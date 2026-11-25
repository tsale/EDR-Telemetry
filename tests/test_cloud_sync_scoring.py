import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def sync(monkeypatch):
    dependencies = {
        'requests': {'RequestException': RuntimeError},
        'supabase': {'Client': object, 'create_client': Mock()},
        'flask': {'Request': object},
    }
    for name, members in dependencies.items():
        module = ModuleType(name)
        for key, value in members.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, name, module)
    path = Path(__file__).resolve().parents[1] / 'Tools' / 'CloudFunction' / 'main.py'
    spec = importlib.util.spec_from_file_location('cloud_sync_scoring_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = [
        {'Telemetry Feature Category': 'Process Activity', 'Sub-Category': 'Process Creation', 'EDR': 'Yes'},
        {'Telemetry Feature Category': None, 'Sub-Category': 'Win32 API Telemetry', 'EDR': 'No'},
    ]
    monkeypatch.setattr(module, 'fetch_json_data', lambda url: [] if 'explanations' in url else rows)
    return module


def response(*data):
    return SimpleNamespace(data=list(data))


def mock_tables(categories):
    db, telemetry, results = Mock(), Mock(), Mock()
    db.table.side_effect = lambda name: telemetry if name.endswith('_telemetry') else results
    telemetry.select.return_value.execute.return_value = response(*categories)
    telemetry.insert.return_value.execute.return_value = response({'id': 3, 'optional': False})
    telemetry.update.return_value.eq.return_value.eq.return_value.execute.return_value = response(
        {'id': 2, 'optional': False}
    )
    results.upsert.return_value.execute.return_value = response({'id': 1})
    return db, telemetry, results


@pytest.mark.parametrize('optional, updates', [(True, 1), (False, 0)])
def test_existing_windows_category_updates_only_when_optional(sync, optional, updates):
    db, telemetry, results = mock_tables([
        {'id': 1, 'category': 'Process Activity', 'subcategory': 'Process Creation', 'optional': True},
        {'id': 2, 'category': 'Process Activity', 'subcategory': 'Win32 API Telemetry', 'optional': optional},
    ])
    stats = sync.update_windows_data(db, 'example/repo', 'commit')
    assert stats['categories_updated'] == updates
    assert telemetry.update.call_count == updates
    if updates:
        telemetry.update.assert_called_once_with({'optional': False})
        telemetry.update.return_value.eq.assert_called_once_with('id', 2)
        telemetry.update.return_value.eq.return_value.eq.assert_called_once_with('optional', True)
    assert results.upsert.call_args.args[0]['status'] == 'No'
    assert results.upsert.call_count == 2


def test_only_new_windows_category_receives_explicit_optional_flag(sync):
    db, telemetry, _ = mock_tables([])
    sync.update_windows_data(db, 'example/repo', 'commit')
    assert [call.args[0] for call in telemetry.insert.call_args_list] == [
        {'category': 'Process Activity', 'subcategory': 'Process Creation'},
        {'category': 'Process Activity', 'subcategory': 'Win32 API Telemetry', 'optional': False},
    ]


@pytest.mark.parametrize('platform', ['linux', 'macos'])
def test_other_platforms_do_not_apply_windows_override(sync, platform):
    db, telemetry, _ = mock_tables([])
    getattr(sync, f'update_{platform}_data')(db, 'example/repo', 'commit')
    assert all('optional' not in call.args[0] for call in telemetry.insert.call_args_list)
    telemetry.update.assert_not_called()
