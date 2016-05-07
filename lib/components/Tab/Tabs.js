'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _Tab = require('../Tab/Tab');

var _Tab2 = _interopRequireDefault(_Tab);

var _Mixin = require('../Mixin/Mixin');

var _Mixin2 = _interopRequireDefault(_Mixin);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Tabs = function (_Component) {
    _inherits(Tabs, _Component);

    function Tabs() {
        var _Object$getPrototypeO;

        var _temp, _this, _ret;

        _classCallCheck(this, Tabs);

        for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
        }

        return _ret = (_temp = (_this = _possibleConstructorReturn(this, (_Object$getPrototypeO = Object.getPrototypeOf(Tabs)).call.apply(_Object$getPrototypeO, [this].concat(args))), _this), _this.state = {
            checked: true
        }, _temp), _possibleConstructorReturn(_this, _ret);
    }

    _createClass(Tabs, [{
        key: 'onChildChanged',
        value: function onChildChanged(newState) {
            this.setState({
                checked: newState
            });
        }
    }, {
        key: 'render',
        value: function render() {
            var isChecked = this.state.checked ? 'yes' : 'no';
            return _react2.default.createElement(
                'div',
                null,
                isChecked,
                _react2.default.createElement(_Tab2.default, { text: 'Toggle me', initialChecked: this.state.checked, callbackParent: this.onChildChanged.bind(this) }),
                _react2.default.createElement(_Mixin2.default, null)
            );
        }
    }]);

    return Tabs;
}(_react.Component);

exports.default = Tabs;