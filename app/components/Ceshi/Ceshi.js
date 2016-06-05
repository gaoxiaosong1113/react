import React, { Component } from 'react';
import Ceshi2 from './Ceshi2';
import $ from 'jQuery';


class Ceshi extends Component {
    state = {
        title: [1,1,2,2]
    }
    componentDidMount() {
        $.ajax({
            type: "GET",
            url: "http://localhost:8080/data/banner.text",
            dataType: "json",
            success: data => {
            	this.setState({ title: data },function(){this.render()})
            }
        })
    }
    render() {
    	console.log(this.state.title)
        return (< Ceshi2 title = { this.state.title }/>)
    }
}

export default Ceshi;
