const Product = require("../models/Product");

const getAllProducts = async (req, res) => {
  try {
    const products = await Product.find();

    res.status(200).json({
      message: "Products fetched successfully",
      products,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      message: "Something went wrong",
    });
  }
};

const createProduct = async (req, res) => {
  try {
    //  create product using model
    const product = await Product.create(req.body);

    // Send created product in response
    res.status(201).json(product);
  } catch (err) {
    console.log(err.message);
    res.status(500).json({
      message: "Something went wrong ",
    });
  }
};

const getProductById = async (req, res) => {
  try {
    // Get product ID from request parameters
    const productId = req.params.id;
    // Get product by ID using findById method
    const product = await Product.findById(productId);

    // If product not found, return 404
    if (!product) {
      // Return 404 status code with 404
      return res.status(404).json({
        message: "Product not found",
      });
    }

    // Send product in response
    res.json(product);
  } catch (err) {
    console.log(err.message);
    res.status(500).json({
      message: "Something went wrong",
    });
  }
};

const updateProduct = async (req, res) => {
  try {
    // Get product ID from request parameters
    const productId = req.params.id;
    // Update product using findByIdAndUpdate method
    const product = await Product.findByIdAndUpdate(productId, req.body, {
      new: true,
    });

    // If product not found, return 404
    if (!product) {
      return res.status(404).json({
        message: "Product not found",
      });
    }

    // Send updated product in response
    res.json(product);
  } catch (err) {
    console.log(err.message);
    res.status(500).json({
      message: "Something went wrong",
    });
  }
};

const deleteProduct = async (req, res) => {
  try {
    // Get product ID from request parameters
    const productId = req.params.id;
    // Delete product using findByIdAndDelete method
    const product = await Product.findByIdAndDelete(productId);

    // If product not found, return 404
    if (!product) {
      return res.status(404).json({
        message: "Product not found",
      });
    }

    // Send success message in response
    res.json({
      message: "Product deleted successfully",
    });
  } catch (err) {
    console.log(err.message);
    res.status(500).json({
      message: "Something went wrong",
    });
  }
};

module.exports = {
  createProduct,
  getAllProducts,
  getProductById,
  updateProduct,
  deleteProduct,
};
