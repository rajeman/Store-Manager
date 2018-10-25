[![Build Status](https://travis-ci.com/rajeman/Store-Manager.svg?branch=develop)](https://travis-ci.com/rajeman/Store-Manager)
[![Maintainability](https://api.codeclimate.com/v1/badges/a0486eea2f1e5fa4df8e/maintainability)](https://codeclimate.com/github/rajeman/Store-Manager/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a0486eea2f1e5fa4df8e/test_coverage)](https://codeclimate.com/github/rajeman/Store-Manager/test_coverage)
[![Coverage Status](https://coveralls.io/repos/github/rajeman/Store-Manager/badge.svg?branch=develop)](https://coveralls.io/github/rajeman/Store-Manager?branch=develop)
# Store-Manager
Store Manager is a web application that allows store owners to manage product sales, inventory and 
records

# Features
* Store attendant can search and add products to buyer’s cart.
* Store attendant can see his/her sale records but can’t modify them.
* App should show available products, quantity and price.
* Store owner can see sales and can filter by attendants.
* Store owner can add, modify and delete products.

# Github Pages
* https://rajeman.github.io/Store-Manager/UI/index.html

# Heroku App
* http://onlinestoremanager.herokuapp.com/

# Project Management
* https://www.pivotaltracker.com/n/projects/2203373
## Running App
* Install Node.js on your computer and run the command: "npm start" at the root directory of the project.
# Testing
* Run "npm test" at the root directory of the project.
# API Routes
| Endpoint  | Functionality | Notes |
| ------------- | ------------- |------------- |
| GET /products  | Fetch a single product  | Get a specific product using the product's id|
|GET /sales|Fetch all sale records|Get all sale records. Endpoint is accessible to only the store owner/admin. Admin must supply the query parameter: "level=2"|
|GET /sales/:saleId|Fetch a single sale record|Get a specific sale record using the id. Endpoint is accessible to  the store owner/admin or the sale attendant that created the record. Admin must supply the query parameter: "level=2". The attendant must supply the query parameter: "attendantId=x", where 'x' is the attendant's id.|
|POST /products|Create a product|Creates a new product record. Endpoint is accessible to only the store owner/admin. Admin must supply the query parameter: "level=2".|
|POST /sales|Create a sale order|Creates a sale order. Endpoint is accessible to only the store owner/admin. Admin must supply the query parameter: "level=2"|
|POST /auth/signup|Register a user |This endpoint creates a new store attendant and is available to only the admin. Admin must be logged in to use this route|


# Credits
* https://pexels.com
* https://w3schools.com
* https://unsplash.com 
* https://stackoverflow.com
 


