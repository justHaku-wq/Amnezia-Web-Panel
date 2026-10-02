"""Fork-only styles live in static/css/fork.css, loaded after style.css.

Two things depend on it: the upstream promo tiles stay hidden, and animations
under an open modal are paused. The modal backdrop blurs the page behind it;
with something animating there the browser re-blurred the whole viewport on
every frame, which made the browser lag for as long as a modal was open.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORK_CSS = (ROOT / 'static' / 'css' / 'fork.css').read_text(encoding='utf-8')
BASE = (ROOT / 'templates' / 'base.html').read_text(encoding='utf-8')


class ForkStylesheetTests(unittest.TestCase):
    def test_base_template_loads_it_after_style_css(self):
        style = BASE.index('/static/css/style.css?v={{ static_v }}')
        fork = BASE.index('/static/css/fork.css?v={{ static_v }}')
        self.assertLess(style, fork)

    def test_promo_tiles_are_hidden(self):
        self.assertRegex(FORK_CSS, r'\.promo-block\s*\{\s*display:\s*none\s*!important;\s*\}')

    def test_animations_under_an_open_modal_are_paused(self):
        rule = re.search(r'body:has\(\.modal-backdrop\.active\)[^{]*\{([^}]*)\}', FORK_CSS)
        self.assertIsNotNone(rule)
        self.assertIn('animation-play-state: paused', rule.group(1))

    def test_the_open_modal_itself_keeps_animating(self):
        selector = FORK_CSS[FORK_CSS.index('body:has('):FORK_CSS.index('{', FORK_CSS.index('body:has('))]
        for part in selector.split(',\n'):
            self.assertIn(':not(.modal-backdrop.active, .modal-backdrop.active *)', part)

    def test_pseudo_elements_are_covered(self):
        self.assertIn('::before', FORK_CSS)
        self.assertIn('::after', FORK_CSS)


if __name__ == '__main__':
    unittest.main()
