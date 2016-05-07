import React, { Component } from 'react';
import Tab from '../Tab/Tab';
import Mixin from '../Mixin/Mixin';

class Tabs extends Component {

    state = {
        checked: true
    }
    onChildChanged(newState) {
        this.setState({
            checked: newState
        });
    }
    render() {
         var isChecked = this.state.checked ? 'yes' : 'no';
        return ( 

            <div>{isChecked}
                < Tab text = "Toggle me" initialChecked={this.state.checked} callbackParent = { this.onChildChanged.bind(this) }/ >
                <Mixin /> 
            </div>
            )
        
        }
    }
    export default Tabs;
