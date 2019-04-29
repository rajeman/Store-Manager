import React from 'react';
import { connect } from 'react-redux';
import { toast } from 'react-toastify';
import CartItem from './CartItem';
import { fetchCartProducts } from '../helpers/cart'; 

class Cart extends React.Component {

    handleCheckout = () => {
        toast('What a Toast!!', {
            hideProgressBar: true
        });

    }
    render() {
        const { email } = this.props.auth.userDetails;
        const products = fetchCartProducts(email) != undefined ? fetchCartProducts(email): [];
        
        return (
            <div className="container">
                <div className="wrapper">
                    <div className="container">
                        <div className="wrapper">
                            <span className="tip">Click on item to remove</span>
                            <input type="button" class="confirm checkout" value="checkout" onClick={this.handleCheckout}></input>
                            <div className="items-box">
                            {products.map((product)=>
                                <CartItem item = {product}/>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        );
    }
}

const mapStateToProps = (state) => state;

export default connect( mapStateToProps)(Cart); 

