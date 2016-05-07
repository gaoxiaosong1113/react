import React, { Component } from 'react';
import Tabs from '../Tab/Tabs';


// 1. 组件命名遵循驼峰命名，首字母大写
class Tab extends Component {
    state = {
        liked: true,
        title: "wode",
        checked: this.props.initialChecked
    }

    handleClick() {
        this.setState({ liked: !this.state.liked });
    }
    onTextChange() {
        var newState = !this.state.checked;
        this.setState({
          checked: newState
        });
        // 这里要注意：setState 是一个异步方法，所以需要操作缓存的当前值
        this.props.callbackParent(newState);
    }
    render() {
        var checked = this.state.checked
        var text = this.props.text
        var isShow = this.state.liked ? 'show' : 'hide'
        var title = this.state.title
        return ( 
            < div >
                < div onClick = { this.handleClick.bind(this) } className = { isShow } > { isShow } < /div> 
                < label >
                    < input type = "checkbox" onChange = { this.onTextChange.bind(this) } checked = { checked }/>  { text } + { title } 
                < /label >  
            < /div>
        )
    }
}

export default Tab;
