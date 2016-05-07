'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _Tabs = require('../Tab/Tabs');

var _Tabs2 = _interopRequireDefault(_Tabs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

// 1. 组件命名遵循驼峰命名，首字母大写

var Tab = function (_Component) {
    _inherits(Tab, _Component);

    function Tab() {
        var _Object$getPrototypeO;

        var _temp, _this, _ret;

        _classCallCheck(this, Tab);

        for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
        }

        return _ret = (_temp = (_this = _possibleConstructorReturn(this, (_Object$getPrototypeO = Object.getPrototypeOf(Tab)).call.apply(_Object$getPrototypeO, [this].concat(args))), _this), _this.state = {
            liked: true,
            title: "wode",
            checked: _this.props.initialChecked
        }, _temp), _possibleConstructorReturn(_this, _ret);
    }

    _createClass(Tab, [{
        key: 'handleClick',
        value: function handleClick() {
            this.setState({ liked: !this.state.liked });
        }
    }, {
        key: 'onTextChange',
        value: function onTextChange() {
            var newState = !this.state.checked;
            this.setState({
                checked: newState
            });
            // 这里要注意：setState 是一个异步方法，所以需要操作缓存的当前值
            this.props.callbackParent(newState);
        }
    }, {
        key: 'render',
        value: function render() {
            var checked = this.state.checked;
            var text = this.props.text;
            var isShow = this.state.liked ? 'show' : 'hide';
            var title = this.state.title;
            return _react2.default.createElement(
                'div',
                null,
                _react2.default.createElement(
                    'div',
                    { onClick: this.handleClick.bind(this), className: isShow },
                    ' ',
                    isShow,
                    ' '
                ),
                _react2.default.createElement(
                    'label',
                    null,
                    _react2.default.createElement('input', { type: 'checkbox', onChange: this.onTextChange.bind(this), checked: checked }),
                    '  ',
                    text,
                    ' + ',
                    title
                )
            );
        }
    }]);

    return Tab;
}(_react.Component);

exports.default = Tab;