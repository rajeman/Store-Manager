import React from 'react';
import { connect } from 'react-redux';
import { history } from '../routers/AppRouter';
import Header from './Header';
import Footer from './Footer';
import Dropdown from './Dropdown';
import DashboardContent from './DashboardContent';
import { setNavigation } from '../actions/navigation';
import { getToken } from '../helpers/auth';

class Dashboard extends React.Component {
    componentDidMount() {
        this.props.dispatch(setNavigation({
           id: this.props.match.params.id,
           urlPath: this.props.match.path
       }));  //not needed again
       //console.log(this.props);
    }
    render() {
       // console.log(this.props);
         // console.log(getToken('Authorization'));
        if(getToken('Authorization') === 'undefined'){
           // console.log(getToken('Authorization'),'auth');
            history.push('/');
            //console.log(this)
        }     
        return (
            <div id = "cover">
                <Header>
                    <Dropdown />
                </Header>
                <DashboardContent />
                <Footer /> 
            </div>
        );
    }
}

const mapStateToProps = (state) => state;


export default connect(mapStateToProps)(Dashboard); 