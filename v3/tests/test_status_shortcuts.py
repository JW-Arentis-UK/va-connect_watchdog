import unittest

from va_watchdog.status_shortcuts import selected_shortcuts, validate_selection


class StatusShortcutsTest(unittest.TestCase):
    def test_known_cards_follow_maintenance_order(self):
        ids = validate_selection(['analytics', 'hardware', 'analytics'])
        self.assertEqual(ids, ['analytics', 'hardware'])
        self.assertEqual([item['id'] for item in selected_shortcuts({'status_shortcuts': ids})], ['hardware', 'analytics'])

    def test_unknown_card_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_selection(['not-a-maintenance-card'])


if __name__ == '__main__':
    unittest.main()
