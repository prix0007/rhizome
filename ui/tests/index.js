// Node 22 does not expand a bare directory argument, so `node --test ui/tests/`
// resolves to this entry file, which loads every test module.
import './graph-model.test.js';
