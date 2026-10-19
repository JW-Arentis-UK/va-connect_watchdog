"""Maintenance links that an operator may pin to the simple Status page."""

OPTIONS = (
    ('identity', 'Gateway identity', '/setup', 'Name this gateway for its site.'),
    ('hardware', 'Hardware watchdog', '/hardware-protection', 'Protection and recovery status.'),
    ('storage', 'Recording storage', '/setup#storage', 'Recording disk and mount setup.'),
    ('analytics', 'Analytics', '/analytics', 'Crossing and ANPR cameras.'),
    ('teamviewer', 'TeamViewer', '/teamviewer', 'Remote support settings.'),
    ('links', 'Web links', '/links', 'Router and camera shortcuts.'),
    ('updates', 'Software updates', '/setup#software-update', 'Installed build and updates.'),
    ('evidence', 'Diagnostics and evidence', '/evidence', 'Logs and incident investigation.'),
    ('reset', 'Reset watchdog data', '/factory-reset', 'Clear site-specific watchdog data.'),
)


def selected_shortcuts(cfg):
    selected = cfg.get('status_shortcuts', [])
    if not isinstance(selected, list):
        selected = []
    return [{'id': key, 'title': title, 'href': href, 'description': description}
            for key, title, href, description in OPTIONS if key in selected]


def validate_selection(ids):
    valid = {option[0] for option in OPTIONS}
    if not isinstance(ids, list) or len(ids) > len(OPTIONS) or any(item not in valid for item in ids):
        raise ValueError('Invalid Maintenance card selection')
    return list(dict.fromkeys(ids))
