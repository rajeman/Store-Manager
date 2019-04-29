import React from 'react';
import { connect } from 'react-redux';
import { toast } from 'react-toastify';
import { fetchProduct, deleteProduct } from '../actions/products';
import { history } from '../routers/AppRouter';
import DeleteModal from '../components/DeleteModal';
import { setDeleteModal } from '../actions/products';
import CartAddModal from './CartAddModal';
import { setAddCartModal } from '../actions/cart';
import { isPositiveInteger } from '../helpers/validators';
import { addProductToCart } from '../helpers/cart';

class ProductDetails extends React.Component {
    componentDidMount () {
        this.props.dispatch(fetchProduct(this.props.id));
    }
    handleCancel = () =>{
        this.props.dispatch(setDeleteModal('STATE_INVISIBLE'));
    }
    handleDelete = () =>{
        this.props.dispatch(deleteProduct(this.props.id));
    }
    handleRemoveModal = () => {
        this.props.dispatch(setAddCartModal('STATE_INVISIBLE'));
    }
    
    handleAddItem = (quantity) => {
           if(!isPositiveInteger(quantity)){
            toast.error('Quantity must be a positive integer!', {
                hideProgressBar: true
            });
               return 
           }
           const { product } = this.props.products;
           if(quantity > product[0].product_quantity){
            toast.error('Quantity is larger than available quantity!', {
                hideProgressBar: true
            });
            return
           }
           const result = addProductToCart(this.props.auth.userDetails.email, product[0]);
           if(result === 'ADD_SUCCESS'){
            toast.success('Product Successfully Added', {
                hideProgressBar: true
            });
           } else if( result === 'DUPLICATE_ITEM'){
            toast.error('Product already in cart. Please remove first', {
                hideProgressBar: true
            });
           } else {
            toast.error('Unknown error occurred', {
                hideProgressBar: true
            });

           }
           this.handleRemoveModal();
    }
    render() {
       // console.log(this.props);
        const { product } = this.props.products;
        const { level } = this.props.auth.userDetails;
        const { deleteModal } = this.props.products;
        const { cartAddModalState } = this.props.cart;
        if(product[0]){
        return (
                <div className="product-details" id="product">
                    <img src={require("../images/item1.jpg")} />
                    <div className="quant-avail">{product[0].product_quantity} available</div>
                    <div className="min-invent">Minimum Inventory: {product[0].minimum_inventory}</div>
                    <div className="name-description detailed-description">{product[0].product_name}</div>
                    
                    <div className="price detailed-price">
                        $<span className="actual-price">{ product[0].product_price }</span> per item
                                </div>
                    
                                { level === 2 && <input type="button" className="confirm modify" id="modify" value="Modify" onClick = {()=>{
                            history.push(`/modify-product/${this.props.id}`);
                    }}></input>}
                    
                    { level === 2 && <input type="button" className="delete" value="Delete" onClick = { ()=>{
                        this.props.dispatch(setDeleteModal('STATE_VISIBLE'));
                    }}></input>}
                    
                    { level === 1 && <input type="button" className="confirm modify"  value="Add to Cart" onClick = {()=>{
                        this.props.dispatch(setAddCartModal('STATE_VISIBLE'));
    
                    }}></input>}
                    
                    {deleteModal === 'STATE_VISIBLE' &&  <DeleteModal handleCancel = {this.handleCancel} handleDelete = {this.handleDelete}/>}
                    {cartAddModalState === 'STATE_VISIBLE' && level === 1 && <CartAddModal handleRemoveModal = {this.handleRemoveModal} handleAddItem = {this.handleAddItem}/>}
                </div>
                
            
            

        );
        } else {
            return <div></div>
        }
    }
}

const mapStateToProps = (state) => state;

export default connect( mapStateToProps)(ProductDetails); 
