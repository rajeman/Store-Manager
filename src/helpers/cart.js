
const verifyProductInCart  = (products, id) => {
    return products.find((product)=>{
        return product.product_id === id;
    });
}

export const addProductToCart = (email, product) => {

    const userItems = JSON.parse(localStorage.getItem(email) != null ? localStorage.getItem(email): '{}' );
    const userProducts = userItems.products != undefined ? userItems.products : [];
    const isProductPresent = verifyProductInCart(userProducts, product.product_id);
    if(isProductPresent){
        return 'DUPLICATE_ITEM';
    }
    userProducts.push(product);
    localStorage.setItem(email, JSON.stringify({
        products: userProducts
    }
    )
        );
    return 'ADD_SUCCESS';
    
}

export const fetchCartProducts = (email) => 
  localStorage.getItem(email) !== null ? JSON.parse(localStorage.getItem(email)).products : [];