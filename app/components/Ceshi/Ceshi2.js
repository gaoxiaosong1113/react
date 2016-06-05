import React, { Component } from 'react';

class Ceshi2 extends Component {
  render(){
  	let notes = this.props.title.map((note, index) => {
      return <li className="list-group-item" key={index}>{note}</li>
    })
    return (
	<ul className="list-group">
		{notes}
  	</ul>)
  }
}

export default Ceshi2;


