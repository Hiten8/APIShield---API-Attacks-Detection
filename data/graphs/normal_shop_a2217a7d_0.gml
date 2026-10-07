graph [
  directed 1
  node [
    id 0
    label "0"
    key "POST /identity/api/auth/login"
    visits 1
  ]
  node [
    id 1
    label "1"
    key "GET /workshop/api/shop/products"
    visits 1
  ]
  node [
    id 2
    label "2"
    key "GET /workshop/api/shop/orders/all"
    visits 1
  ]
  edge [
    source 0
    target 1
    count 1
    mean_dt 6.7597
  ]
  edge [
    source 1
    target 2
    count 1
    mean_dt 4.5396
  ]
]
