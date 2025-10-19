import streamlit as st
import requests
import json
import hmac
import hashlib
import urllib.parse
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
import base64
import time
from threading import Thread
import uuid

# Configuración con tus credenciales
BSALE_ACCESS_TOKEN = 'c08427dba8f06cbf22608864eac6f2a0ad0a3f5a'
BSALE_BASE_URL = 'https://api.bsale.io/v1'

# Falabella credentials
FALABELLA_USER_ID = 'rodolfo@grupoescocia.cl'
FALABELLA_API_KEY = '1b823c0738471081d0337a9cb42d86215d1c5f6f'
FALABELLA_BASE_URL = 'https://sellercenter-api.falabella.com'

OFFICE_ID = 1  # Tu office principal
PRICE_LIST_ID = 2  # Lista de precios fija

# Walmart credentials
WALMART_CLIENT_ID = '1e115056-e49a-4935-a188-9701d55bfbda'
WALMART_CLIENT_SECRET = 'ALCQs6lhu8PAMw5pKw0yXr3Z5lZs4QQ0TFeW3oe_KdSQVukmSVC7RmkORKHVScW2fM0HsgojXzspAP9dsJTpQbY'
WALMART_PARTNER_ID = '10001403176'
WALMART_TOKEN_URL = 'https://marketplace.walmartapis.com/v3/token'
WALMART_INVENTORY_URL = 'https://marketplace.walmartapis.com/v3/inventory'

headers_bsale = {
    'access_token': BSALE_ACCESS_TOKEN,
    'Content-Type': 'application/json'
}

# Estado global
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'progress' not in st.session_state:
    st.session_state.progress = 0
if 'total_tasks' not in st.session_state:
    st.session_state.total_tasks = 0
if 'boletas_emitidas' not in st.session_state:
    st.session_state.boletas_emitidas = []
if 'boletas_no_emitidas' not in st.session_state:
    st.session_state.boletas_no_emitidas = []
if 'pdfs_subidos' not in st.session_state:
    st.session_state.pdfs_subidos = []
if 'pdfs_no_subidos' not in st.session_state:
    st.session_state.pdfs_no_subidos = []
if 'stocks_sincronizados_walmart' not in st.session_state:
    st.session_state.stocks_sincronizados_walmart = []
if 'stocks_no_sincronizados_walmart' not in st.session_state:
    st.session_state.stocks_no_sincronizados_walmart = []
if 'stocks_sincronizados_falabella' not in st.session_state:
    st.session_state.stocks_sincronizados_falabella = []
if 'stocks_no_sincronizados_falabella' not in st.session_state:
    st.session_state.stocks_no_sincronizados_falabella = []
if 'skus_fallidos' not in st.session_state:
    st.session_state.skus_fallidos = []

def log(message):
    st.session_state.logs.append(message)
    st.experimental_rerun()  # Actualiza la UI en tiempo real

# Funciones comunes
def generate_signature(api_key, parameters):
    sorted_params = sorted(parameters.items())
    concatenated = urllib.parse.urlencode(sorted_params)
    signature = hmac.new(api_key.encode('utf-8'), concatenated.encode('utf-8'), hashlib.sha256).hexdigest()
    return signature

# Falabella (Boletas)
def call_falabella_api(action, params=None, xml_body=None, method='GET'):
    timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    if params is None:
        params = {}
    params.update({
        'Action': action,
        'UserID': FALABELLA_USER_ID,
        'Timestamp': timestamp,
        'Version': '1.0',
        'Format': 'XML'
    })
    params['Signature'] = generate_signature(FALABELLA_API_KEY, params)
    url = f"{FALABELLA_BASE_URL}/?{urllib.parse.urlencode(params)}"
    headers = {'Content-Type': 'application/json'}
    if xml_body:
        headers['Content-Type'] = 'text/xml; charset=utf-8'
        method = 'POST'
    try:
        if method == 'POST':
            response = requests.post(url, data=xml_body, headers=headers, timeout=60)
        else:
            response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        content = response.text
        log(f"Debug: Respuesta raw de Falabella ({action}): {content[:500]}...")
        if 'ErrorResponse' in content:
            root = ET.fromstring(content)
            error_msg = root.find('.//ErrorMessage')
            if error_msg is not None:
                log(f"Error Falabella {action}: {error_msg.text}")
            return None
        elif 'SuccessResponse' in content:
            root = ET.fromstring(content)
            return root
        else:
            log(f"Respuesta inesperada en {action}")
            return None
    except ET.ParseError as e:
        log(f"Error parsing XML en {action}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        log(f"Error request en {action}: {e}")
        return None

def obtener_orden_por_numero(order_number):
    found_order = None
    limit = 100
    offset = 0
    max_offset = 1000
    while offset < max_offset:
        params = {
            'Limit': str(limit),
            'Offset': str(offset),
            'SortBy': 'created_at',
            'SortDirection': 'DESC'
        }
        root = call_falabella_api('GetOrders', params=params)
        if root is None:
            break
        orders = parse_orders_from_xml(root)
        for order in orders:
            if order.get('OrderNumber') == order_number:
                found_order = order
                log(f"  ✓ Orden encontrada: ID {order.get('OrderId')}, OrderNumber {order_number}")
                return found_order
        fetched = len(orders)
        log(f"  Fetched {fetched} orders (total so far: {fetched + offset})")
        if fetched < limit:
            break
        offset += limit
    log(f"  ✗ No se encontró la orden con OrderNumber {order_number} en las últimas {offset} órdenes.")
    return None

def parse_orders_from_xml(root):
    body = root.find('.//Body')
    if body is None:
        log("  ✗ No Body en XML response.")
        return []
    orders_elem = body.find('Orders')
    if orders_elem is None:
        log("  ✗ No Orders en Body.")
        return []
    orders = []
    for order_elem in orders_elem.findall('Order'):
        order = {}
        for child in order_elem:
            order[child.tag] = child.text
        orders.append(order)
    log(f"  ✓ Parseados {len(orders)} órdenes del XML.")
    return orders

def obtener_detalles_orden_falabella(order_id):
    params = {'OrderId': str(order_id)}
    root = call_falabella_api('GetOrder', params=params)
    if root is None:
        log(f"  ✗ GetOrder falló para {order_id}")
        return None
    body = root.find('.//Body')
    if body is None:
        log(f"  ✗ No Body en GetOrder para {order_id}")
        return None
    orders_elem = body.find('Orders')
    if orders_elem is None:
        log(f"  ✗ No Orders en Body para {order_id}")
        return None
    order_elem = orders_elem.find('Order')
    if order_elem is None:
        log(f"  ✗ No Order en Orders para {order_id}")
        return None
    order = {}
    for child in order_elem:
        order[child.tag] = child.text
    log(f"  ✓ Detalles de orden {order_id} parseados: Cliente {order.get('CustomerFirstName', 'N/A')} {order.get('CustomerLastName', 'N/A')}")
    params_items = {'OrderId': str(order_id)}
    json_resp = call_falabella_api('GetOrderItems', params=params_items, format='JSON')
    items = []
    if json_resp is None or not isinstance(json_resp, dict):
        log(f"✗ Falló GetOrderItems para {order_id}")
    else:
        body = json_resp.get('SuccessResponse', {}).get('Body', {})
        order_items = body.get('OrderItems', {}).get('OrderItem', {})
        if isinstance(order_items, list):
            for item in order_items:
                items.append(item)
        elif isinstance(order_items, dict):
            items.append(order_items)
        log(f"  ✓ {len(items)} items parseados para orden {order_id}")
        if items:
            log(f"  Debug: Tags del primer item: {list(items[0].keys())}")
    order['Items'] = items
    return order

def obtener_pdf_url_bsale(doc_id):
    url = f"{BSALE_BASE_URL}/documents/{doc_id}.json"
    try:
        response = requests.get(url, headers=headers_bsale)
        log(f"  Debug: Status Code para documento BSale: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        pdf_url = data.get('urlPdf')
        if not pdf_url:
            log("  ✗ No se encontró urlPdf en la respuesta de BSale.")
            return None
        log(f"  ✓ URL PDF encontrada: {pdf_url}")
        return pdf_url
    except Exception as e:
        log(f"Error al obtener URL PDF de BSale: {e}")
        return None

def descargar_pdf(pdf_url):
    try:
        response = requests.get(pdf_url)
        response.raise_for_status()
        log(f"  Debug: PDF descargado (tamaño: {len(response.content)} bytes)")
        return response.content
    except Exception as e:
        log(f"Error descargando PDF: {e}")
        return None

def subir_pdf_a_falabella(order_id, invoice_number, invoice_date, pdf_bytes, order_items):
    pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
    seller_order_items = [item['OrderItemId'] for item in order_items]
    payload = {
        "invoiceType": "BOLETA",
        "operatorCode": "FACL",
        "invoiceDocumentFormat": "pdf",
        "orderItemIds": seller_order_items,
        "invoiceNumber": str(invoice_number),
        "invoiceDate": invoice_date,
        "invoiceDocument": pdf_base64
    }
    json_body = json.dumps(payload)
    log(f"  Debug: JSON Body para SetInvoicePDF: {json_body[:500]}...")
    
    parameters = {}
    parameters['Action'] = 'SetInvoicePDF'
    parameters['Format'] = 'JSON'
    parameters['Service'] = 'Invoice'
    parameters['UserID'] = FALABELLA_USER_ID
    parameters['Timestamp'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    parameters['Version'] = '1.0'
    signature = generate_signature(FALABELLA_API_KEY, parameters)
    parameters['Signature'] = signature

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Action": parameters['Action'],
        "Format": parameters['Format'],
        "Service": parameters['Service'],
        "Timestamp": parameters['Timestamp'],
        "UserID": parameters['UserID'],
        "Version": parameters['Version'],
        "Signature": parameters['Signature']
    }

    try:
        response = requests.post('https://sellercenter-api.falabella.com/v1/marketplace-sellers/invoice/pdf', data=json_body, headers=headers)
        content = response.text
        log(f"Debug: Response body (status {response.status_code}): {content}")
        response.raise_for_status()
        if 'ErrorResponse' in content:
            log(f"Error: {content}")
            return False
        log(f"  ✓ PDF subido a Falabella (OrderId {order_id}, InvoiceNumber {invoice_number})")
        return True
    except Exception as e:
        error_msg = str(e)
        if 'response' in locals():
            error_msg += f" | Response body: {response.text}"
        log(f"Error en subida: {error_msg}")
        return False

def crear_boleta_y_subir_pdf(orden_falabella):
    global boletas_emitidas, boletas_no_emitidas, pdfs_subidos, pdfs_no_subidos
    orden_id = orden_falabella.get('OrderId')
    order_number = orden_falabella.get('OrderNumber')
    
    total = float(orden_falabella.get('Price', 0) or 0)
    sub_total = total / 1.19
    tax = total - sub_total
    details = []
    mapeados = 0
    for item in orden_falabella.get('Items', []):
        sku = item.get('SellerSku') or item.get('Sku') or item.get('ProductSku')
        if not sku:
            log(f"  ✗ No SKU encontrado en item {item.get('OrderItemId', 'N/A')}: Tags disponibles: {list(item.keys())}")
            continue
        quantity_str = item.get('Quantity', '1') or '1'
        try:
            quantity = int(quantity_str)
            if quantity <= 0:
                log(f"  ✗ Quantity inválido ({quantity_str}), usando 1")
                quantity = 1
        except ValueError:
            log(f"  ✗ Quantity no numérico ({quantity_str}), usando 1")
            quantity = 1
        log(f"  Debug: Item {item.get('OrderItemId', 'N/A')} - Quantity: {quantity}")
        price = float(item.get('PaidPrice', 0) or 0)
        net_unit_value = price / 1.19 if price > 0 else 0
        variante = obtener_variant_bsale_por_code(sku)
        if variante:
            variant_id = variante.get('id')
            details.append({
                "variantId": variant_id,
                "netUnitValue": int(net_unit_value),
                "quantity": quantity,
                "taxId": "[1]",  # IVA 19%
                "discount": 0
            })
            log(f"    Mapeado: SKU {sku} → variant ID {variant_id}")
            mapeados += 1
        else:
            log(f"  ✗ No se encontró variante para SKU {sku} in BSale")
            boletas_no_emitidas.append((order_number, orden_id, f"No se encontró variante para SKU {sku}"))
            return False
    if not details:
        log(f"✗ No items mapeados para orden {orden_id} (verifica SKUs en BSale)")
        boletas_no_emitidas.append((order_number, orden_id, "No items mapeados"))
        return False
    emission_date = int(datetime.now(timezone.utc).timestamp())
    if emission_date < 1592784000:  # Min 22/06/2020
        log("  ✗ Fecha inválida, usando actual.")
        emission_date = int(datetime.now(timezone.utc).timestamp())
    expiration_date = emission_date
    client = {
        "code": "12345678-9",  # RUT genérico
        "city": "Santiago",
        "company": f"{orden_falabella.get('CustomerFirstName', 'Cliente')} {orden_falabella.get('CustomerLastName', '')}".strip(),
        "municipality": "Santiago",
        "activity": "Comercio al por menor",
        "address": "Dirección genérica"
    }
    payments = [{
        "paymentTypeId": 1,  # Efectivo
        "amount": total,
        "recordDate": emission_date
    }]
    references = [{
        "number": int(orden_id),
        "referenceDate": emission_date,
        "reason": "Orden de Compra Falabella",
        "codeSii": 801
    }]
    payload = {
        "codeSii": 39,  # Boleta electrónica
        "officeId": OFFICE_ID,
        "emissionDate": emission_date,
        "expirationDate": expiration_date,
        "declareSii": 1,
        "priceListId": PRICE_LIST_ID,
        "client": client,
        "details": details,
        "payments": payments,
        "references": references,
        "dispatch": 1  # Despacho inmediato
    }
    log(f"  Debug: Payload para BSale: {json.dumps(payload, indent=2)}")
    url = f"{BSALE_BASE_URL}/documents.json"
    try:
        response = requests.post(url, headers=headers_bsale, data=json.dumps(payload))
        response.raise_for_status()
        resultado = response.json()
        doc_id = resultado.get('id')
        folio = resultado.get('number')  # Folio de SII
        if not folio:
            log("✗ No se obtuvo el folio de la boleta.")
            boletas_no_emitidas.append((order_number, orden_id, "No se obtuvo el folio de la boleta"))
            return False
        log(f"✓ Boleta creada: Doc ID {doc_id}, Folio {folio} para orden {orden_id}")
        boletas_emitidas.append((order_number, orden_id, folio))
        # Obtener URL PDF
        pdf_url = obtener_pdf_url_bsale(doc_id)
        if not pdf_url:
            pdfs_no_subidos.append((order_number, orden_id, folio, "No se obtuvo URL PDF"))
            return False
        # Descargar PDF
        pdf_bytes = descargar_pdf(pdf_url)
        if not pdf_bytes:
            pdfs_no_subidos.append((order_number, orden_id, folio, "Error descargando PDF"))
            return False
        # Subir PDF a Falabella
        invoice_date = datetime.fromtimestamp(emission_date, timezone.utc).strftime('%Y-%m-%d')
        success, error_msg = subir_pdf_a_falabella(orden_id, folio, invoice_date, pdf_bytes, orden_falabella['Items'])
        if success:
            pdfs_subidos.append((order_number, orden_id, folio))
            return True
        else:
            pdfs_no_subidos.append((order_number, orden_id, folio, error_msg or "Error desconocido al subir PDF"))
            return False
    except requests.exceptions.HTTPError as e:
        error_msg = f"Error HTTP {e.response.status_code}: {e.response.text[:200]}"
        log(f"✗ Error HTTP en BSale: {error_msg}")
        boletas_no_emitidas.append((order_number, orden_id, error_msg))
        return False
    except Exception as e:
        log(f"✗ Error creando boleta para {orden_id}: {e}")
        boletas_no_emitidas.append((order_number, orden_id, str(e)))
        return False

# Walmart functions
def get_walmart_token():
    credentials = f"{WALMART_CLIENT_ID}:{WALMART_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    headers = {
        'Authorization': f'Basic {encoded_credentials}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'WM_MARKET': 'cl',
        'WM_QOS.CORRELATION_ID': str(uuid.uuid4()),
        'WM_SVC.NAME': 'Token',
        'WM_SOCIO.ID': WALMART_PARTNER_ID,
        'WM_CONSUMER.CHANNEL.TYPE': 'default'
    }
    payload = {'grant_type': 'client_credentials'}
    try:
        response = requests.post(WALMART_TOKEN_URL, headers=headers, data=payload)
        log(f"Status: {response.status_code}")
        log(f"Response headers: {dict(response.headers)}")
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 900)
            log(f"✓ Token generado exitosamente. Expira en {expires_in} segundos.")
            return access_token
        else:
            log(f"✗ Error {response.status_code}: {response.text}")
            return None
    except Exception as e:
        log(f"✗ Error al obtener token: {e}")
        return None

def get_walmart_auth_header(access_token):
    correlation_id = str(uuid.uuid4())
    headers = {
        'WM_SEC.ACCESS_TOKEN': access_token,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'WM_MARKET': 'cl',
        'WM_QOS.CORRELATION_ID': correlation_id,
        'WM_SVC.NAME': 'Inventory',
        'WM_SOCIO.ID': WALMART_PARTNER_ID,
        'WM_PARTNER.ID': WALMART_PARTNER_ID,
        'WM_CONSUMER.CHANNEL.TYPE': 'default'
    }
    log(f"Debug: Headers para API call: {headers}")
    return headers

def obtener_stock_bsale(sku):
    url = f"{BSALE_BASE_URL}/stocks.json?code={sku}"
    log(f"Buscando stock en BSale para SKU: {sku}")
    try:
        response = requests.get(url, headers=headers_bsale)
        log(f"Status Code BSale: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            log(f"Debug: Response completa de BSale: {json.dumps(data, indent=2)}")
            stocks = data.get('items', [])
            if stocks:
                total_stock = sum(stock.get('quantityAvailable', 0) for stock in stocks)
                log(f"✓ Total stock en BSale para {sku}: {total_stock} unidades")
                return total_stock
            else:
                log(f"✗ No se encontró el SKU {sku} en BSale.")
                return None
        else:
            log(f"✗ Error en BSale API: {response.text[:200]}...")
            return None
    except Exception as e:
        log(f"✗ Error al consultar BSale: {e}")
        return None

def actualizar_stock_walmart(sku, cantidad, access_token):
    url = WALMART_INVENTORY_URL
    headers = get_walmart_auth_header(access_token)
    if not headers:
        return False
    payload = {
        "sku": sku,
        "quantity": {"amount": cantidad, "unit": "EACH"}
    }
    log(f"Actualizando stock en Walmart para SKU {sku}: {cantidad} unidades")
    try:
        response = requests.put(url, headers=headers, json=payload)
        log(f"Status Code Walmart: {response.status_code}")
        log(f"Response: {response.text[:200]}...")
        if response.status_code == 200:
            log(f"✓ Stock actualizado exitosamente para SKU {sku}: {cantidad} unidades")
            stocks_sincronizados_walmart.append((sku, cantidad))
            return True
        else:
            log(f"✗ Error en Walmart API: {response.text[:200]}...")
            stocks_no_sincronizados_walmart.append((sku, f"Error {response.status_code}: {response.text[:50]}"))
            return False
    except Exception as e:
        log(f"✗ Error al actualizar Walmart: {e}")
        stocks_no_sincronizados_walmart.append((sku, str(e)))
        return False

# Falabella stock functions
def obtener_stock_por_sku(sku):
    url = f"{BSALE_BASE_URL}/stocks.json?officeId={OFFICE_ID}&limit=1&code={sku}"
    try:
        response = requests.get(url, headers=headers_bsale, timeout=60)
        response.raise_for_status()
        data_stocks = response.json()
        stocks = data_stocks.get('items', [])
        if stocks:
            stock_item = stocks[0]
            quantity = stock_item.get('quantity', 0)
            reserved = stock_item.get('quantityReserved', 0)
            available = stock_item.get('quantityAvailable', quantity - reserved)
            log(f" ✓ Stock para {sku}: {available}")
            return max(0, available)
        else:
            log(f" ✗ No stock para {sku}")
            return 0
    except requests.exceptions.RequestException as e:
        log(f"Error stock {sku}: {e}")
        return 0

def actualizar_stock_falabella(sku, quantity):
    if quantity == 0:
        log(f" ¡Advertencia! Stock 0 para {sku}, omitido.")
        return True
    request = Element('Request')
    warehouse = SubElement(request, 'Warehouse')
    stock_elem = SubElement(warehouse, 'Stock')
    SubElement(stock_elem, 'SellerSku').text = sku
    SubElement(stock_elem, 'Quantity').text = str(int(quantity))
    xml_body = tostring(request, encoding='utf-8', method='xml').decode('utf-8')
    result = call_falabella_api('UpdateStock', xml_body=xml_body)
    if result is not None:
        log(f" ✓ Actualizado {quantity} unidades para {sku}")
        stocks_sincronizados_falabella.append((sku, quantity))
        return True
    else:
        log(f" ✗ Falló UpdateStock para {sku}")
        stocks_no_sincronizados_falabella.append((sku, "Fallo en UpdateStock"))
        return False

def procesar_boletas(order_numbers):
    st.session_state.total_tasks = len(order_numbers)
    st.session_state.progress = 0
    
    for order_number in order_numbers:
        st.session_state.progress += 1
        progress = st.session_state.progress / st.session_state.total_tasks
        st.progress(progress)
        log(f"\nProcesando OrderNumber {order_number}...")
        orden = obtener_orden_por_numero(order_number)
        if orden:
            detalles = obtener_detalles_orden_falabella(orden['OrderId'])
            if detalles:
                if crear_boleta_y_subir_pdf(detalles):
                    log(f"✅ Boleta emitida, PDF descargado y subido para OrderNumber {order_number} (OrderId {orden['OrderId']})")
                else:
                    log(f"❌ Falló procesamiento de OrderNumber {order_number}")
            else:
                log(f"❌ Falló obtención de detalles para OrderNumber {order_number}")
        else:
            log(f"❌ No se encontró OrderNumber {order_number}")
    
    st.progress(1.0)
    print_resumen()

def procesar_sincronizacion_walmart(skus):
    st.session_state.total_tasks = len(skus)
    st.session_state.progress = 0
    access_token = get_walmart_token()
    if not access_token:
        log("✗ No se pudo obtener token de Walmart. Verifica credenciales.")
        return
    
    for sku in skus:
        st.session_state.progress += 1
        progress = st.session_state.progress / st.session_state.total_tasks
        st.progress(progress)
        log(f"\nSincronizando SKU {sku} con Walmart...")
        stock_bsale = obtener_stock_bsale(sku)
        if stock_bsale is not None:
            if actualizar_stock_walmart(sku, stock_bsale, access_token):
                pass  # Ya registrado en logs
            else:
                pass  # Ya registrado en logs
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")
    
    st.progress(1.0)
    print_resumen_walmart()

def procesar_sincronizacion_falabella(skus):
    st.session_state.total_tasks = len(skus)
    st.session_state.progress = 0
    
    for sku in skus:
        st.session_state.progress += 1
        progress = st.session_state.progress / st.session_state.total_tasks
        st.progress(progress)
        log(f"\nSincronizando SKU {sku} con Falabella...")
        stock_bsale = obtener_stock_por_sku(sku)
        if stock_bsale is not None:
            if actualizar_stock_falabella(sku, stock_bsale):
                pass  # Ya registrado en logs
            else:
                pass  # Ya registrado en logs
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")
    
    st.progress(1.0)
    print_resumen_falabella()

def procesar_sincronizacion_automatica():
    st.session_state.total_tasks = 1  # Solo un proceso automático
    st.session_state.progress = 0
    log("Iniciando sincronización automática de todos los SKUs de BSale a Falabella...")
    sincronizar_stock_todos_productos()
    st.session_state.progress = 1
    st.progress(1.0)
    print_resumen_falabella()

def sincronizar_stock_todos_productos():
    log(" Sincronización de Stock Completa BSale → Falabella")
    log(f"Iniciando a las {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    productos = obtener_todas_variantes_bsale()
    if not productos:
        log("No se pudieron obtener productos de BSale.")
        return
    
    exitosos = 0
    fallidos = 0
    total_productos = len(productos)
    skus_fallidos = []
    
    for i, variante in enumerate(productos, 1):
        sku = variante.get('code', '').strip()
        if not sku:
            log(f" Variante sin SKU: {variante.get('description', 'N/A')}")
            fallidos += 1
            continue
        try:
            stock = obtener_stock_por_sku(sku)
            if stock > 0:
                if actualizar_stock_falabella(sku, stock):
                    exitosos += 1
                else:
                    fallidos += 1
            else:
                log(f" Stock 0 para {sku}, omitido.")
                fallidos += 1
                skus_fallidos.append(sku)
            if i % 100 == 0 or i == total_productos:
                log(f" Progreso: {i}/{total_productos} productos procesados ({exitosos} exitosos, {fallidos} fallidos)")
        except Exception as e:
            log(f" ✗ Error procesando {sku}: {e}")
            fallidos += 1
    log(f" Sincronización completada: {exitosos} exitosos, {fallidos} fallidos de {total_productos} productos.")
    if skus_fallidos:
        log(f" SKUs con stock 0 (omitidos): {len(skus_fallidos)} de {total_productos}")
        st.session_state.skus_fallidos = skus_fallidos

def obtener_todas_variantes_bsale():
    offset = 0
    limit = 100
    todas_variantes = []
    total_count = 0
    log("Obteniendo todas las variantes de BSale...")
    while True:
        url = f"{BSALE_BASE_URL}/variants.json?offset={offset}&limit={limit}"
        try:
            response = requests.get(url, headers=headers_bsale, timeout=90)
            log(f"  Debug: Fetching variants page offset={offset}, limit={limit} (status: {response.status_code})")
            response.raise_for_status()
            data = response.json()
            variantes = data.get('items', [])
            total_count = data.get('count', 0)
            log(f"  Procesando {len(variantes)} variantes en esta página. Total estimado: {total_count}")
            todas_variantes.extend(variantes)
            if offset + len(variantes) >= total_count:
                break
            offset += limit
            time.sleep(0.5)  # Evitar rate limit
        except requests.exceptions.RequestException as e:
            log(f"Error al fetch variantes página {offset}: {e}")
            break
    log(f" ✓ Total variantes obtenidas: {len(todas_variantes)} (de {total_count} totales)")
    return todas_variantes

def print_resumen():
    st.subheader("📊 Resumen de Emisión de Boletas")
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Boletas emitidas", len(st.session_state.boletas_emitidas))
        st.metric("Boletas no emitidas", len(st.session_state.boletas_no_emitidas))
    with col2:
        st.metric("PDFs subidos", len(st.session_state.pdfs_subidos))
        st.metric("PDFs no subidos", len(st.session_state.pdfs_no_subidos))
    
    if st.session_state.boletas_emitidas:
        st.write("**Boletas emitidas:**")
        st.dataframe([{'OrderNumber': on, 'OrderId': oid, 'Folio': folio} for on, oid, folio in st.session_state.boletas_emitidas])
    
    if st.session_state.boletas_no_emitidas:
        st.write("**Boletas no emitidas:**")
        st.dataframe([{'OrderNumber': on, 'OrderId': oid, 'Motivo': motivo} for on, oid, motivo in st.session_state.boletas_no_emitidas])
    
    if st.session_state.pdfs_subidos:
        st.write("**PDFs subidos:**")
        st.dataframe([{'OrderNumber': on, 'OrderId': oid, 'Folio': folio} for on, oid, folio in st.session_state.pdfs_subidos])
    
    if st.session_state.pdfs_no_subidos:
        st.write("**PDFs no subidos:**")
        st.dataframe([{'OrderNumber': on, 'OrderId': oid, 'Folio': folio, 'Motivo': motivo} for on, oid, folio, motivo in st.session_state.pdfs_no_subidos])

def print_resumen_walmart():
    st.subheader("📊 Resumen de Sincronización con Walmart")
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Stocks sincronizados", len(st.session_state.stocks_sincronizados_walmart))
        st.metric("Stocks no sincronizados", len(st.session_state.stocks_no_sincronizados_walmart))
    
    if st.session_state.stocks_sincronizados_walmart:
        st.write("**Stocks sincronizados con Walmart:**")
        st.dataframe([{'SKU': sku, 'Cantidad': cant} for sku, cant in st.session_state.stocks_sincronizados_walmart])
    
    if st.session_state.stocks_no_sincronizados_walmart:
        st.write("**Stocks no sincronizados con Walmart:**")
        st.dataframe([{'SKU': sku, 'Motivo': motivo} for sku, motivo in st.session_state.stocks_no_sincronizados_walmart])

def print_resumen_falabella():
    st.subheader("📊 Resumen de Sincronización con Falabella")
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Stocks sincronizados", len(st.session_state.stocks_sincronizados_falabella))
        st.metric("Stocks no sincronizados", len(st.session_state.stocks_no_sincronizados_falabella))
    with col2:
        st.metric("SKUs con stock 0", len(st.session_state.skus_fallidos))
    
    if st.session_state.stocks_sincronizados_falabella:
        st.write("**Stocks sincronizados con Falabella:**")
        st.dataframe([{'SKU': sku, 'Cantidad': cant} for sku, cant in st.session_state.stocks_sincronizados_falabella])
    
    if st.session_state.stocks_no_sincronizados_falabella:
        st.write("**Stocks no sincronizados con Falabella:**")
        st.dataframe([{'SKU': sku, 'Motivo': motivo} for sku, motivo in st.session_state.stocks_no_sincronizados_falabella])
    
    if st.session_state.skus_fallidos:
        st.write("**SKUs con stock 0 (omitidos):**")
        st.dataframe([{'SKU': sku} for sku in st.session_state.skus_fallidos])

if __name__ == "__main__":
    st.title("📦 Gestión de Inventario y Boletas")
    st.write("Selecciona una tarea y usa los campos para ingresar datos. Haz clic en el botón correspondiente para procesar.")

    # Sección 1: Emisión de Boletas para Falabella
    st.header("1. Emitir Boletas para Falabella")
    order_numbers_input = st.text_area("Ingresa los OrderNumbers (separados por coma o tab)", height=100, help="Ejemplo: 3006204140,3007437418 o 12345\t67890")
    if st.button("Emitir Boletas"):
        if order_numbers_input:
            order_numbers_input = order_numbers_input.replace('\t', ',')
            order_numbers = list(set([num.strip() for num in order_numbers_input.split(',') if num.strip()]))
            if order_numbers:
                Thread(target=procesar_boletas, args=(order_numbers,), daemon=True).start()
            else:
                st.error("Entrada inválida. Usa números de orden separados por coma o tab.")
        else:
            st.error("Por favor, ingresa al menos un OrderNumber.")

    # Sección 2: Sincronización de Stock BSale a Walmart
    st.header("2. Sincronizar Stock con Walmart")
    skus_walmart_input = st.text_area("Ingresa los SKUs para sincronizar con Walmart (separados por coma o tab)", height=100, help="Ejemplo: BVSTBMH23052,ABC123")
    if st.button("Sincronizar con Walmart"):
        if skus_walmart_input:
            skus_walmart_input = skus_walmart_input.replace('\t', ',')
            skus = list(set([sku.strip() for sku in skus_walmart_input.split(',') if sku.strip()]))
            if skus:
                Thread(target=procesar_sincronizacion_walmart, args=(skus,), daemon=True).start()
            else:
                st.error("Entrada inválida. Usa SKUs separados por coma o tab.")
        else:
            st.error("Por favor, ingresa al menos un SKU.")

    # Sección 3: Sincronización de Stock BSale a Falabella
    st.header("3. Sincronizar Stock con Falabella")
    skus_falabella_input = st.text_area("Ingresa los SKUs para sincronizar con Falabella (separados por coma o tab)", height=100, help="Ejemplo: BVSTBMH23052,XYZ789")
    if st.button("Sincronizar con Falabella"):
        if skus_falabella_input:
            skus_falabella_input = skus_falabella_input.replace('\t', ',')
            skus = list(set([sku.strip() for sku in skus_falabella_input.split(',') if sku.strip()]))
            if skus:
                Thread(target=procesar_sincronizacion_falabella, args=(skus,), daemon=True).start()
            else:
                st.error("Entrada inválida. Usa SKUs separados por coma o tab.")
        else:
            st.error("Por favor, ingresa al menos un SKU.")

    # Sección 4: Sincronización Automática BSale → Falabella
    st.header("4. Sincronización Automática de Todos los SKUs con Falabella")
    st.write("Esto sincroniza todos los productos de BSale con Falabella. No requiere input.")
    if st.button("Iniciar Sincronización Automática"):
        Thread(target=procesar_sincronizacion_automatica, daemon=True).start()

    # Mostrar logs en tiempo real
    st.subheader("📝 Logs")
    for log_msg in st.session_state.logs:
        st.write(log_msg)

    # Mostrar resúmenes
    print_resumen()
    print_resumen_walmart()
    print_resumen_falabella()