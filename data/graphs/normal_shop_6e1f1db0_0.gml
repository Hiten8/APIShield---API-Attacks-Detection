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
    visits 3
  ]
  node [
    id 2
    label "2"
    key "POST /workshop/api/shop/orders"
    visits 1
  ]
  node [
    id 3
    label "3"
    key "GET /workshop/api/shop/orders/{order_id}"
    visits 2
  ]
  node [
    id 4
    label "4"
    key "GET /workshop/api/shop/orders/all"
    visits 1
  ]
  edge [
    source 0
    target 1
    count 1
    mean_dt 3.9108
  ]
  edge [
    source 1
    target 1
    count 2
    mean_dt 36.9487
  ]
  edge [
    source 1
    target 2
    count 1
    mean_dt 28.9711
  ]
  edge [
    source 2
    target 3
    count 1
    mean_dt 5.6387
  ]
  edge [
    source 3
    target 4
    count 1
    mean_dt 5.7307
  ]
  edge [
    source 4
    target 3
    count 1
    mean_dt 26.8827
  ]
]
