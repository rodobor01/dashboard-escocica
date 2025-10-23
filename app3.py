from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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
from functools import wraps
import os  # Agregado para env vars

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tu_clave_secreta_aqui_cambia_por_una_segura')  # Usa env var en prod

# Configuración con tus credenciales (usa env vars para seguridad en Render)
BSALE_ACCESS_TOKEN = os.environ.get('BSALE_ACCESS_TOKEN', 'c08427dba8f06cbf22608864eac6f2a0ad0a3f5a')
BSALE_BASE_URL = 'https://api.bsale.io/v1'
FALABELLA_USER_ID = os.environ.get('FALABELLA_USER_ID', 'rodolfo@grupoescocia.cl')
FALABELLA_API_KEY = os.environ.get('FALABELLA_API_KEY', '1b823c0738471081d0337a9cb42d86215d1c5f6f')
FALABELLA_BASE_URL = 'https://sellercenter-api.falabella.com'
OFFICE_ID = 1
PRICE_LIST_ID = 2
WALMART_CLIENT_ID = os.environ.get('WALMART_CLIENT_ID', '1e115056-e49a-4935-a188-9701d55bfbda')
WALMART_CLIENT_SECRET = os.environ.get('WALMART_CLIENT_SECRET', 'ALCQs6lhu8PAMw5pKw0yXr3Z5lZs4QQ0TFeW3oe_KdSQVukmSVC7RmkORKHVScW2fM0HsgojXzspAP9dsJTpQbY')
WALMART_PARTNER_ID = '10001403176'
WALMART_TOKEN_URL = 'https://marketplace.walmartapis.com/v3/token'
WALMART_ITEMS_URL = 'https://marketplace.walmartapis.com/v3/items'
WALMART_INVENTORY_URL = 'https://marketplace.walmartapis.com/v3/inventory'

headers_bsale = {'access_token': BSALE_ACCESS_TOKEN, 'Content-Type': 'application/json'}

# Inicializar sesión si no existe
def init_session():
    if 'logs' not in session:
        session['logs'] = []
    if 'boletas_emitidas' not in session:
        session['boletas_emitidas'] = []
    if 'boletas_no_emitidas' not in session:
        session['boletas_no_emitidas'] = []
    if 'pdfs_subidos' not in session:
        session['pdfs_subidos'] = []
    if 'pdfs_no_subidos' not in session:
        session['pdfs_no_subidos'] = []
    if 'stocks_sincronizados_walmart' not in session:
        session['stocks_sincronizados_walmart'] = []
    if 'stocks_no_sincronizados_walmart' not in session:
        session['stocks_no_sincronizados_walmart'] = []
    if 'stocks_sin_inventario_walmart' not in session:
        session['stocks_sin_inventario_walmart'] = []
    if 'stocks_sincronizados_falabella' not in session:
        session['stocks_sincronizados_falabella'] = []
    if 'stocks_no_sincronizados_falabella' not in session:
        session['stocks_no_sincronizados_falabella'] = []

def log(message):
    session['logs'].append(message)
    # Para Flask, no hay rerun, pero puedes guardar y redirigir después

def generate_signature(api_key, parameters):
    sorted_params = sorted(parameters.items())
    concatenated = urllib.parse.urlencode(sorted_params)
    signature = hmac.new(api_key.encode('utf-8'), concatenated.encode('utf-8'), hashlib.sha256).hexdigest()
    return signature

# Función corregida para call_falabella_api con soporte para JSON
def call_falabella_api(action, params=None, xml_body=None, method='GET', fmt='XML'):
    timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    if params is None:
        params = {}
    params.update({'Action': action, 'UserID': FALABELLA_USER_ID, 'Timestamp': timestamp, 'Version': '1.0', 'Format': fmt})
    params['Signature'] = generate_signature(FALABELLA_API_KEY, params)
    url = f"{FALABELLA_BASE_URL}/?{urllib.parse.urlencode(params)}"
    headers = {'Content-Type': 'application/json'}
    if xml_body:
        headers['Content-Type'] = 'text/xml; charset=utf-8'
        method = 'POST'
    try:
        log(f"Iniciando llamada a Falabella: {action}")
        if method == 'POST':
            response = requests.post(url, data=xml_body, headers=headers, timeout=30)
        else:
            response = requests.get(url, headers=headers, timeout=30)
        content = response.text
        log(f"Debug: Respuesta raw de Falabella ({action}, status {response.status_code}): {content[:500]}...")
        response.raise_for_status()
        if fmt == 'XML':
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
        else:  # JSON
            try:
                data = json.loads(content)
                if 'ErrorResponse' in data:
                    log(f"Error Falabella {action}: {data.get('ErrorResponse', {})}")
                    return None
                elif 'SuccessResponse' in data:
                    return data['SuccessResponse']
                else:
                    log(f"Respuesta inesperada en {action}")
                    return None
            except json.JSONDecodeError as e:
                log(f"Error parsing JSON en {action}: {e}")
                return None
    except ET.ParseError as e:
        log(f"Error parsing XML en {action}: {e}")
        flash(f"Error parsing XML en {action}: {e}", 'error')
        return None
    except requests.exceptions.Timeout:
        log(f"Timeout en {action}: La solicitud tardó demasiado.")
        flash(f"Timeout en {action}. Verifica la conexión o el servicio.", 'error')
        return None
    except requests.exceptions.RequestException as e:
        log(f"Error request en {action}: {e}")
        flash(f"Error en {action}: {e}", 'error')
        return None

def obtener_orden_por_numero(order_number):
    log(f"Iniciando búsqueda de orden {order_number}")
    found_order = None
    limit = 100
    offset = 0
    max_offset = 1000
    while offset < max_offset:
        params = {'Limit': str(limit), 'Offset': str(offset), 'SortBy': 'created_at', 'SortDirection': 'DESC'}
        log(f"Llamando GetOrders con offset {offset}")
        root = call_falabella_api('GetOrders', params=params)
        if root is None:
            log(f"GetOrders falló para offset {offset}")
            break
        orders = parse_orders_from_xml(root)
        for order in orders:
            if order.get('OrderNumber') == order_number:
                found_order = order
                log(f" ✓ Orden encontrada: ID {order.get('OrderId')}, OrderNumber {order_number}")
                return found_order
        fetched = len(orders)
        log(f" Fetched {fetched} orders (total so far: {fetched + offset})")
        if fetched < limit:
            break
        offset += limit
    log(f" ✗ No se encontró la orden con OrderNumber {order_number} en las últimas {offset} órdenes.")
    return None

def parse_orders_from_xml(root):
    body = root.find('.//Body')
    if body is None:
        log(" ✗ No Body en XML response.")
        return []
    orders_elem = body.find('Orders')
    if orders_elem is None:
        log(" ✗ No Orders en Body.")
        return []
    orders = []
    for order_elem in orders_elem.findall('Order'):
        order = {}
        for child in order_elem:
            order[child.tag] = child.text
        orders.append(order)
    log(f" ✓ Parseados {len(orders)} órdenes del XML.")
    return orders

def obtener_detalles_orden_falabella(order_id):
    log(f"Iniciando GetOrder para {order_id}")
    params = {'OrderId': str(order_id)}
    root = call_falabella_api('GetOrder', params=params)
    if root is None:
        log(f" ✗ GetOrder falló para {order_id}")
        return None
    body = root.find('.//Body')
    if body is None:
        log(f" ✗ No Body en GetOrder para {order_id}")
        return None
    orders_elem = body.find('Orders')
    if orders_elem is None:
        log(f" ✗ No Orders en Body para {order_id}")
        return None
    order_elem = orders_elem.find('Order')
    if order_elem is None:
        log(f" ✗ No Order en Orders para {order_id}")
        return None
    order = {}
    for child in order_elem:
        order[child.tag] = child.text
    log(f" ✓ Detalles de orden {order_id} parseados: Cliente {order.get('CustomerFirstName', 'N/A')} {order.get('CustomerLastName', 'N/A')}")
    params_items = {'OrderId': str(order_id)}
    log(f"Iniciando GetOrderItems para {order_id}")
    json_resp = call_falabella_api('GetOrderItems', params=params_items, fmt='JSON')
    items = []
    if json_resp is None:
        log(f"✗ Falló GetOrderItems para {order_id}")
    else:
        body = json_resp.get('Body', {})
        order_items = body.get('OrderItems', {}).get('OrderItem', {})
        if isinstance(order_items, list):
            for item in order_items:
                items.append(item)
        elif isinstance(order_items, dict):
            items.append(order_items)
        log(f" ✓ {len(items)} items parseados para orden {order_id}")
        if items:
            log(f" Debug: Tags del primer item: {list(items[0].keys())}")
    order['Items'] = items
    return order

# Función mejorada con logging detallado, retry y timeout alto
def obtener_variant_bsale_por_code(code):
    url = f"{BSALE_BASE_URL}/products.json?code={code}"
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            log(f"Buscando variante en BSale para code {code} (intento {attempt + 1}/{max_retries + 1})")
            log(f"URL: {url}")
            log(f"Headers: { {k: v if k != 'access_token' else '***HIDDEN***' for k,v in headers_bsale.items() } }")  # Oculta token
            
            # Usa session para reutilizar conexión (mejora estabilidad)
            session_req = requests.Session()
            response = session_req.get(
                url, 
                headers=headers_bsale, 
                timeout=60,  # Aumentado por latencia en cloud
                verify=False  # Temporal: deshabilita SSL verify para test (quita en prod si no es necesario)
            )
            
            log(f"Status code: {response.status_code}")
            log(f"Response headers: {dict(response.headers)}")  # Para debug red
            
            response.raise_for_status()
            data = response.json()
            log(f"Data keys: {list(data.keys()) if data else 'None'}")
            log(f"Items count: {len(data.get('items', [])) if data else 0}")
            
            if data and 'items' in data and data['items']:
                product = data['items'][0]
                if 'variants' in product and product['variants']:
                    variant = product['variants'][0]  # Toma la primera variante
                    log(f" ✓ Variante encontrada para {code}: ID {variant.get('id')}")
                    return variant
                else:
                    log(f" ✗ Producto encontrado pero sin variants para {code}")
                    return None
            else:
                log(f" ✗ No se encontró producto para {code} (items vacíos)")
                return None
                
        except requests.exceptions.RequestException as req_e:
            log(f"Request error para {code} (intento {attempt + 1}): {type(req_e).__name__}: {req_e}")
            if hasattr(req_e, 'response') and req_e.response is not None:
                log(f"Response status en error: {req_e.response.status_code}")
                log(f"Response text en error: {req_e.response.text[:200]}")
            if attempt < max_retries:
                log(f" Reintentando en 2s...")
                time.sleep(2)
                continue
            else:
                log(f" ✗ Falló después de {max_retries + 1} intentos")
                return None
                
        except Exception as e:
            log(f"Unexpected error para {code} (intento {attempt + 1}): {type(e).__name__}: {e}")
            if attempt < max_retries:
                time.sleep(2)
                continue
            return None
    
    return None

def obtener_pdf_url_bsale(doc_id):
    log(f"Iniciando obtención de PDF para doc_id {doc_id}")
    url = f"{BSALE_BASE_URL}/documents/{doc_id}.json"
    try:
        response = requests.get(url, headers=headers_bsale, timeout=30)
        log(f" Debug: Status Code para documento BSale: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        pdf_url = data.get('urlPdf')
        if not pdf_url:
            log(" ✗ No se encontró urlPdf en la respuesta de BSale.")
            return None
        log(f" ✓ URL PDF encontrada: {pdf_url}")
        return pdf_url
    except requests.exceptions.Timeout:
        log("Timeout al obtener URL PDF de BSale.")
        flash("Timeout al obtener URL PDF de BSale. Verifica la conexión.", 'error')
        return None
    except Exception as e:
        log(f"Error al obtener URL PDF de BSale: {e}")
        flash(f"Error al obtener URL PDF de BSale: {e}", 'error')
        return None

def descargar_pdf(pdf_url):
    log(f"Iniciando descarga de PDF: {pdf_url}")
    try:
        response = requests.get(pdf_url, timeout=30)
        response.raise_for_status()
        log(f" Debug: PDF descargado (tamaño: {len(response.content)} bytes)")
        return response.content
    except requests.exceptions.Timeout:
        log("Timeout al descargar PDF.")
        flash("Timeout al descargar PDF. Verifica la conexión.", 'error')
        return None
    except Exception as e:
        log(f"Error descargando PDF: {e}")
        flash(f"Error al descargar PDF: {e}", 'error')
        return None

# Corregida para retornar (success, error_msg)
def subir_pdf_a_falabella(order_id, invoice_number, invoice_date, pdf_bytes, order_items):
    log(f"Iniciando subida de PDF para OrderId {order_id}")
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
    log(f" Debug: JSON Body para SetInvoicePDF: {json_body[:500]}...")
   
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
        response = requests.post('https://sellercenter-api.falabella.com/v1/marketplace-sellers/invoice/pdf', data=json_body, headers=headers, timeout=30)
        content = response.text
        log(f"Debug: Response body (status {response.status_code}): {content}")
        response.raise_for_status()
        if 'ErrorResponse' in content:
            error_msg = content
            log(f"Error: {content}")
            return False, error_msg
        log(f" ✓ PDF subido a Falabella (OrderId {order_id}, InvoiceNumber {invoice_number})")
        return True, None
    except requests.exceptions.Timeout:
        error_msg = "Timeout al subir PDF a Falabella."
        log(error_msg)
        flash(error_msg, 'error')
        return False, error_msg
    except Exception as e:
        error_msg = str(e)
        if 'response' in locals():
            error_msg += f" | Response body: {response.text}"
        log(f"Error en subida: {error_msg}")
        flash(f"Error al subir PDF a Falabella: {error_msg}", 'error')
        return False, error_msg

def crear_boleta_y_subir_pdf(orden_falabella):
    init_session()  # Asegurar sesión
    log(f"Iniciando creación de boleta para OrderId {orden_falabella.get('OrderId')}")
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
            log(f" ✗ No SKU encontrado en item {item.get('OrderItemId', 'N/A')}: Tags disponibles: {list(item.keys())}")
            continue
        quantity_str = item.get('Quantity', '1') or '1'
        try:
            quantity = int(quantity_str)
            if quantity <= 0:
                log(f" ✗ Quantity inválido ({quantity_str}), usando 1")
                quantity = 1
        except ValueError:
            log(f" ✗ Quantity no numérico ({quantity_str}), usando 1")
            quantity = 1
        log(f" Debug: Item {item.get('OrderItemId', 'N/A')} - Quantity: {quantity}")
        price = float(item.get('PaidPrice', 0) or 0)
        net_unit_value = price / 1.19 if price > 0 else 0
        variante = obtener_variant_bsale_por_code(sku)
        if variante:
            variant_id = variante.get('id')
            details.append({
                "variantId": variant_id,
                "netUnitValue": int(net_unit_value),
                "quantity": quantity,
                "taxId": "[1]", # IVA 19%
                "discount": 0
            })
            log(f" Mapeado: SKU {sku} → variant ID {variant_id}")
            mapeados += 1
        else:
            log(f" ✗ No se encontró variante para SKU {sku} in BSale")
            session['boletas_no_emitidas'].append((order_number, orden_id, f"No se encontró variante para SKU {sku}"))
            return False
    if not details:
        log(f"✗ No items mapeados para orden {orden_id} (verifica SKUs en BSale)")
        session['boletas_no_emitidas'].append((order_number, orden_id, "No items mapeados"))
        return False
    emission_date = int(datetime.now(timezone.utc).timestamp())
    if emission_date < 1592784000: # Min 22/06/2020
        log(" ✗ Fecha inválida, usando actual.")
        emission_date = int(datetime.now(timezone.utc).timestamp())
    expiration_date = emission_date
    # Corregido: usar CustomerTaxId si existe
    customer_tax_id = orden_falabella.get('CustomerTaxId', '12345678-9')
    client = {
        "code": customer_tax_id,
        "city": "Santiago",
        "company": f"{orden_falabella.get('CustomerFirstName', 'Cliente')} {orden_falabella.get('CustomerLastName', '')}".strip(),
        "municipality": "Santiago",
        "activity": "Comercio al por menor",
        "address": "Dirección genérica"
    }
    payments = [{
        "paymentTypeId": 1, # Efectivo
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
        "codeSii": 39, # Boleta electrónica
        "officeId": OFFICE_ID,
        "emissionDate": emission_date,
        "expirationDate": expiration_date,
        "declareSii": 1,
        "priceListId": PRICE_LIST_ID,
        "client": client,
        "details": details,
        "payments": payments,
        "references": references,
        "dispatch": 1 # Despacho inmediato
    }
    log(f" Debug: Payload para BSale: {json.dumps(payload, indent=2)}")
    url = f"{BSALE_BASE_URL}/documents.json"
    try:
        log(f"Iniciando creación de boleta en BSale")
        response = requests.post(url, headers=headers_bsale, data=json.dumps(payload), timeout=30)
        log(f"Response from BSale: status {response.status_code}")
        response.raise_for_status()
        resultado = response.json()
        doc_id = resultado.get('id')
        folio = resultado.get('number') # Folio de SII
        if not folio:
            log("✗ No se obtuvo el folio de la boleta.")
            session['boletas_no_emitidas'].append((order_number, orden_id, "No se obtuvo el folio de la boleta"))
            return False
        log(f"✓ Boleta creada: Doc ID {doc_id}, Folio {folio} para orden {orden_id}")
        session['boletas_emitidas'].append((order_number, orden_id, folio))
        # Obtener URL PDF
        log(f"Iniciando obtención de PDF para doc_id {doc_id}")
        pdf_url = obtener_pdf_url_bsale(doc_id)
        if not pdf_url:
            session['pdfs_no_subidos'].append((order_number, orden_id, folio, "No se obtuvo URL PDF"))
            return False
        # Descargar PDF
        log(f"Iniciando descarga de PDF")
        pdf_bytes = descargar_pdf(pdf_url)
        if not pdf_bytes:
            session['pdfs_no_subidos'].append((order_number, orden_id, folio, "Error descargando PDF"))
            return False
        # Subir PDF a Falabella
        log(f"Iniciando subida de PDF para OrderId {orden_id}")
        invoice_date = datetime.fromtimestamp(emission_date, timezone.utc).strftime('%Y-%m-%d')
        success, error_msg = subir_pdf_a_falabella(orden_id, folio, invoice_date, pdf_bytes, orden_falabella['Items'])
        if success:
            session['pdfs_subidos'].append((order_number, orden_id, folio))
            return True
        else:
            session['pdfs_no_subidos'].append((order_number, orden_id, folio, error_msg or "Error desconocido al subir PDF"))
            return False
    except requests.exceptions.Timeout:
        log("Timeout al crear boleta en BSale.")
        flash("Timeout al crear boleta en BSale. Verifica la conexión.", 'error')
        session['boletas_no_emitidas'].append((order_number, orden_id, "Timeout en BSale"))
        return False
    except requests.exceptions.HTTPError as e:
        error_msg = f"Error HTTP {e.response.status_code}: {e.response.text[:200]}"
        log(f"✗ Error HTTP en BSale: {error_msg}")
        flash(f"Error HTTP en BSale: {error_msg}", 'error')
        session['boletas_no_emitidas'].append((order_number, orden_id, error_msg))
        return False
    except Exception as e:
        log(f"✗ Error creando boleta para {orden_id}: {e}")
        flash(f"Error creando boleta para {orden_id}: {e}", 'error')
        session['boletas_no_emitidas'].append((order_number, orden_id, str(e)))
        return False

# Funciones de Walmart (mismas que original, pero con session en lugar de st.session_state)
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
        log(f"Iniciando obtención de token Walmart")
        response = requests.post(WALMART_TOKEN_URL, headers=headers, data=payload, timeout=30)
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
            flash(f"Error al obtener token de Walmart: {response.text}", 'error')
            return None
    except requests.exceptions.Timeout:
        log("Timeout al obtener token de Walmart.")
        flash("Timeout al obtener token de Walmart. Verifica la conexión.", 'error')
        return None
    except Exception as e:
        log(f"✗ Error al obtener token: {e}")
        flash(f"Error al obtener token de Walmart: {e}", 'error')
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

def obtener_items_walmart(access_token):
    offset = 0
    limit = 50
    existing_skus = []
    url = f"{WALMART_ITEMS_URL}?limit={limit}&offset={offset}&status=ACTIVE"
    headers = get_walmart_auth_header(access_token)
    try:
        while True:
            log(f"Iniciando fetching de items Walmart, offset {offset}")
            response = requests.get(url, headers=headers, timeout=30)
            log(f" Debug: Fetching items from Walmart (offset={offset}, status={response.status_code})")
            if response.status_code != 200:
                log(f"✗ Error fetching items: {response.text[:200]}")
                flash(f"Error al obtener items de Walmart: {response.text[:200]}", 'error')
                break
            data = response.json()
            items = data.get('ItemResponse', [])
            log(f" Debug: Number of items in ItemResponse: {len(items)}")
            for item in items:
                sku = item.get('sku')
                if sku:
                    existing_skus.append(sku)
            fetched = len(items)
            log(f" Processed {fetched} items (total so far: {len(existing_skus)})")
            if fetched < limit:
                break
            offset += limit
            url = f"{WALMART_ITEMS_URL}?limit={limit}&offset={offset}&status=ACTIVE"
            time.sleep(1)
        return existing_skus
    except requests.exceptions.Timeout:
        log("Timeout al obtener items de Walmart.")
        flash("Timeout al obtener items de Walmart. Verifica la conexión.", 'error')
        return []
    except Exception as e:
        log(f"✗ Error obtaining Walmart items: {e}")
        flash(f"Error al obtener items de Walmart: {e}", 'error')
        return []

def obtener_stock_bsale(sku):
    url = f"{BSALE_BASE_URL}/stocks.json?code={sku}"
    try:
        log(f"Iniciando consulta de stock BSale para {sku}")
        response = requests.get(url, headers=headers_bsale, timeout=30)
        log(f"Status Code BSale: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            stocks = data.get('items', [])
            if stocks:
                total_stock = sum(stock.get('quantityAvailable', 0) for stock in stocks)
                log(f"✓ Total stock en BSale para {sku}: {total_stock} unidades")
                if total_stock == 0:
                    log(f"⚠ Stock 0 para {sku}. Saltando automáticamente.")
                    return None
                return total_stock
            else:
                log(f"✗ No se encontró el SKU {sku} en BSale.")
                return None
        else:
            log(f"✗ Error en BSale API: {response.text[:200]}...")
            flash(f"Error en BSale API: {response.text[:200]}", 'error')
            return None
    except requests.exceptions.Timeout:
        log("Timeout al consultar stock de BSale.")
        flash("Timeout al consultar stock de BSale. Verifica la conexión.", 'error')
        return None
    except Exception as e:
        log(f"✗ Error al consultar BSale: {e}")
        flash(f"Error al consultar BSale: {e}", 'error')
        return None

def verificar_inventario_walmart(sku, access_token):
    url = f"{WALMART_INVENTORY_URL}/{sku}"
    headers = get_walmart_auth_header(access_token)
    try:
        log(f"Iniciando verificación de inventario para {sku}")
        response = requests.get(url, headers=headers, timeout=30)
        log(f" Debug: Inventory check for {sku}, status={response.status_code}, body={response.text[:200]}...")
        if response.status_code == 200:
            log(f" ✓ SKU {sku} encontrado en inventario.")
            return True
        else:
            log(f" ✗ SKU {sku} no encontrado en inventario: {response.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        log("Timeout al verificar inventario de Walmart.")
        flash("Timeout al verificar inventario de Walmart. Verifica la conexión.", 'error')
        return False
    except Exception as e:
        log(f" ✗ Error checking inventory for {sku}: {e}")
        flash(f"Error al verificar inventario de Walmart: {e}", 'error')
        return False

def actualizar_stock_walmart(sku, quantity, access_token):
    if not verificar_inventario_walmart(sku, access_token):
        session['stocks_sin_inventario_walmart'].append((sku, "SKU no encontrado en inventario (404)"))
        return False
    url = f"{WALMART_INVENTORY_URL}/{sku}"
    headers = get_walmart_auth_header(access_token)
    payload = {
        "sku": sku,
        "quantity": {"amount": quantity, "unit": "EACH"}
    }
    try:
        log(f"Iniciando actualización de stock para {sku}")
        response = requests.put(url, headers=headers, json=payload, timeout=30)
        log(f"Status Code Walmart: {response.status_code}")
        log(f"Response: {response.text[:200]}...")
        if response.status_code == 200:
            log(f"✓ Stock actualizado en Walmart para SKU {sku}: {quantity} unidades")
            session['stocks_sincronizados_walmart'].append((sku, quantity))
            return True
        else:
            log(f"✗ Error updating Walmart stock for {sku}: {response.text[:200]}...")
            session['stocks_no_sincronizados_walmart'].append((sku, f"Error {response.status_code}: {response.text[:50]}"))
            flash(f"Error al actualizar stock de Walmart para {sku}: {response.text[:200]}", 'error')
            return False
    except requests.exceptions.Timeout:
        log("Timeout al actualizar stock de Walmart.")
        flash("Timeout al actualizar stock de Walmart. Verifica la conexión.", 'error')
        session['stocks_no_sincronizados_walmart'].append((sku, "Timeout en Walmart"))
        return False
    except Exception as e:
        log(f"✗ Error updating Walmart stock: {e}")
        session['stocks_no_sincronizados_walmart'].append((sku, str(e)))
        flash(f"Error al actualizar stock de Walmart: {e}", 'error')
        return False

def obtener_items_falabella():
    offset = 0
    limit = 100
    existing_skus = set()
    while True:
        params = {'Limit': str(limit), 'Offset': str(offset)}
        root = call_falabella_api('GetItems', params=params)
        if root is None:
            break
        body = root.find('.//Body')
        if body is None:
            break
        items_elem = body.find('Items')
        if items_elem is None:
            break
        for item in items_elem.findall('Item'):
            sku = item.find('SellerSku')
            if sku is not None and sku.text:
                existing_skus.add(sku.text.strip())
        fetched = len(items_elem.findall('Item'))
        log(f" Fetching items from Falabella: offset={offset}, fetched={fetched}")
        if fetched < limit:
            break
        offset += limit
        time.sleep(1)
    return existing_skus

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
        log(f" ✓ Actualizado {quantity} unidades para {sku} en Falabella")
        session['stocks_sincronizados_falabella'].append((sku, quantity))
        return True
    else:
        log(f" ✗ Falló UpdateStock para {sku} en Falabella")
        session['stocks_no_sincronizados_falabella'].append((sku, "Fallo en UpdateStock"))
        flash(f"Falló UpdateStock para {sku} en Falabella", 'error')
        return False

# Funciones de procesamiento (adaptadas sin progress bar, ya que Flask no es interactivo por defecto)
def procesar_boletas(order_numbers):
    init_session()
    for order_number in order_numbers:
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

def procesar_sincronizacion_walmart(skus):
    init_session()
    access_token = get_walmart_token()
    if not access_token:
        log("✗ No se pudo obtener token de Walmart. Verifica credenciales.")
        flash("No se pudo obtener token de Walmart. Verifica credenciales.", 'error')
        return
   
    for sku in skus:
        log(f"\nSincronizando SKU {sku} con Walmart...")
        stock_bsale = obtener_stock_bsale(sku)
        if stock_bsale is not None:
            actualizar_stock_walmart(sku, stock_bsale, access_token)
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")

def procesar_sincronizacion_falabella(skus):
    init_session()
    for sku in skus:
        log(f"\nSincronizando SKU {sku} con Falabella...")
        stock_bsale = obtener_stock_bsale(sku)
        if stock_bsale is not None:
            actualizar_stock_falabella(sku, stock_bsale)
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")

def procesar_sincronizacion_automatica_falabella():
    init_session()
    log("Iniciando sincronización automática de todos los SKUs de Falabella con BSale...")
    skus_existentes = obtener_items_falabella()
    for sku in skus_existentes:
        log(f"\nSincronizando SKU {sku} de Falabella con BSale...")
        stock_bsale = obtener_stock_bsale(sku)
        if stock_bsale is not None:
            actualizar_stock_falabella(sku, stock_bsale)
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")
        time.sleep(1)

def procesar_sincronizacion_automatica_walmart():
    init_session()
    log("Iniciando sincronización automática de todos los SKUs de Walmart con BSale...")
    access_token = get_walmart_token()
    if not access_token:
        log("✗ No se pudo obtener token de Walmart. Verifica credenciales.")
        flash("No se pudo obtener token de Walmart. Verifica credenciales.", 'error')
        return
    skus_existentes = obtener_items_walmart(access_token)
    for sku in skus_existentes:
        log(f"\nSincronizando SKU {sku} de Walmart con BSale...")
        stock_bsale = obtener_stock_bsale(sku)
        if stock_bsale is not None:
            actualizar_stock_walmart(sku, stock_bsale, access_token)
        else:
            log(f"✗ No se pudo obtener stock de BSale para {sku}")
        time.sleep(1)

# Funciones para renderizar resúmenes en HTML (simplificadas)
def render_resumen_boletas():
    emitidas = len(session.get('boletas_emitidas', []))
    no_emitidas = len(session.get('boletas_no_emitidas', []))
    subidos = len(session.get('pdfs_subidos', []))
    no_subidos = len(session.get('pdfs_no_subidos', []))
    html = f"""
    <h3>📊 Resumen de Emisión de Boletas</h3>
    <p><strong>Boletas emitidas:</strong> {emitidas}</p>
    <p><strong>Boletas no emitidas:</strong> {no_emitidas}</p>
    <p><strong>PDFs subidos:</strong> {subidos}</p>
    <p><strong>PDFs no subidos:</strong> {no_subidos}</p>
    """
    if session.get('boletas_emitidas'):
        html += "<h4>Boletas emitidas:</h4><table><tr><th>OrderNumber</th><th>OrderId</th><th>Folio</th></tr>"
        for on, oid, folio in session['boletas_emitidas']:
            html += f"<tr><td>{on}</td><td>{oid}</td><td>{folio}</td></tr>"
        html += "</table>"
    if session.get('boletas_no_emitidas'):
        html += "<h4>Boletas no emitidas:</h4><table><tr><th>OrderNumber</th><th>OrderId</th><th>Motivo</th></tr>"
        for on, oid, motivo in session['boletas_no_emitidas']:
            html += f"<tr><td>{on}</td><td>{oid}</td><td>{motivo}</td></tr>"
        html += "</table>"
    if session.get('pdfs_no_subidos'):
        html += "<h4>PDFs no subidos:</h4><table><tr><th>OrderNumber</th><th>OrderId</th><th>Folio</th><th>Motivo</th></tr>"
        for on, oid, folio, motivo in session['pdfs_no_subidos']:
            html += f"<tr><td>{on}</td><td>{oid}</td><td>{folio}</td><td>{motivo}</td></tr>"
        html += "</table>"
    return html

def render_resumen_walmart():
    sincronizados = len(session.get('stocks_sincronizados_walmart', []))
    no_sincronizados = len(session.get('stocks_no_sincronizados_walmart', []))
    sin_inventario = len(session.get('stocks_sin_inventario_walmart', []))
    html = f"""
    <h3>📊 Resumen de Sincronización con Walmart</h3>
    <p><strong>Stocks sincronizados:</strong> {sincronizados}</p>
    <p><strong>Stocks no sincronizados:</strong> {no_sincronizados}</p>
    <p><strong>SKUs sin inventario:</strong> {sin_inventario}</p>
    """
    if session.get('stocks_sincronizados_walmart'):
        html += "<h4>Stocks sincronizados:</h4><table><tr><th>SKU</th><th>Cantidad</th></tr>"
        for sku, cant in session['stocks_sincronizados_walmart']:
            html += f"<tr><td>{sku}</td><td>{cant}</td></tr>"
        html += "</table>"
    if session.get('stocks_no_sincronizados_walmart'):
        html += "<h4>Stocks no sincronizados:</h4><table><tr><th>SKU</th><th>Motivo</th></tr>"
        for sku, motivo in session['stocks_no_sincronizados_walmart']:
            html += f"<tr><td>{sku}</td><td>{motivo}</td></tr>"
        html += "</table>"
    return html

def render_resumen_falabella():
    sincronizados = len(session.get('stocks_sincronizados_falabella', []))
    no_sincronizados = len(session.get('stocks_no_sincronizados_falabella', []))
    html = f"""
    <h3>📊 Resumen de Sincronización con Falabella</h3>
    <p><strong>Stocks sincronizados:</strong> {sincronizados}</p>
    <p><strong>Stocks no sincronizados:</strong> {no_sincronizados}</p>
    """
    if session.get('stocks_sincronizados_falabella'):
        html += "<h4>Stocks sincronizados:</h4><table><tr><th>SKU</th><th>Cantidad</th></tr>"
        for sku, cant in session['stocks_sincronizados_falabella']:
            html += f"<tr><td>{sku}</td><td>{cant}</td></tr>"
        html += "</table>"
    if session.get('stocks_no_sincronizados_falabella'):
        html += "<h4>Stocks no sincronizados:</h4><table><tr><th>SKU</th><th>Motivo</th></tr>"
        for sku, motivo in session['stocks_no_sincronizados_falabella']:
            html += f"<tr><td>{sku}</td><td>{motivo}</td></tr>"
        html += "</table>"
    return html

# Ruta principal
@app.route('/', methods=['GET', 'POST'])
def index():
    init_session()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'emitir_boletas':
            order_numbers_input = request.form.get('order_numbers', '')
            if order_numbers_input:
                order_numbers_input = order_numbers_input.replace('\t', ',')
                order_numbers = [num.strip() for num in order_numbers_input.split(',') if num.strip()]
                order_numbers = list(set(order_numbers))  # Eliminar duplicados
                if order_numbers:
                    procesar_boletas(order_numbers)
                    flash('Procesamiento de boletas completado. Revisa los logs y resúmenes.', 'success')
                else:
                    flash('Entrada inválida. Usa números de orden separados por coma o tab.', 'error')
            else:
                flash('Por favor, ingresa al menos un OrderNumber.', 'error')
        elif action == 'actualizar_falabella':
            skus_input = request.form.get('skus_falabella', '')
            if skus_input:
                skus_input = skus_input.replace('\t', ',')
                skus = [sku.strip() for sku in skus_input.split(',') if sku.strip()]
                skus = list(set(skus))
                if skus:
                    procesar_sincronizacion_falabella(skus)
                    flash('Sincronización con Falabella completada.', 'success')
                else:
                    flash('Entrada inválida. Usa SKUs separados por coma o tab.', 'error')
            else:
                flash('Por favor, ingresa al menos un SKU.', 'error')
        elif action == 'actualizar_todos_falabella':
            Thread(target=procesar_sincronizacion_automatica_falabella, daemon=True).start()
            flash('Sincronización automática con Falabella iniciada en background. Revisa logs periódicamente.', 'info')
        elif action == 'actualizar_walmart':
            skus_input = request.form.get('skus_walmart', '')
            if skus_input:
                skus_input = skus_input.replace('\t', ',')
                skus = [sku.strip() for sku in skus_input.split(',') if sku.strip()]
                skus = list(set(skus))
                if skus:
                    procesar_sincronizacion_walmart(skus)
                    flash('Sincronización con Walmart completada.', 'success')
                else:
                    flash('Entrada inválida. Usa SKUs separados por coma o tab.', 'error')
            else:
                flash('Por favor, ingresa al menos un SKU.', 'error')
        elif action == 'actualizar_todos_walmart':
            Thread(target=procesar_sincronizacion_automatica_walmart, daemon=True).start()
            flash('Sincronización automática con Walmart iniciada en background. Revisa logs periódicamente.', 'info')
        return redirect(url_for('index'))

    # Renderizar página principal con logs y resúmenes
    logs_html = '<h3>📝 Logs</h3><ul>' + ''.join([f'<li>{msg}</li>' for msg in session['logs'][-50:]]) + '</ul>'  # Últimos 50 logs
    res_boletas = render_resumen_boletas()
    res_walmart = render_resumen_walmart()
    res_falabella = render_resumen_falabella()

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Gestión de Inventario y Boletas - Flask</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            form {{ margin-bottom: 20px; }}
            textarea {{ width: 100%; height: 100px; }}
            button {{ padding: 10px; margin: 5px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>📦 Gestión de Inventario y Boletas</h1>
        <p>Selecciona una tarea y usa los campos para ingresar datos. Haz clic en el botón correspondiente para procesar.</p>

        <h2>1. Emitir Boletas para Falabella</h2>
        <form method="post">
            <textarea name="order_numbers" placeholder="Ingresa los OrderNumbers (separados por coma o tab). Ejemplo: 3006204140,3007437418">{"" if not request.form else request.form.get('order_numbers', '')}</textarea>
            <button type="submit" name="action" value="emitir_boletas">Emitir Boletas</button>
        </form>

        <h2>2. Actualizar Stock de Ciertos SKUs en Falabella</h2>
        <form method="post">
            <textarea name="skus_falabella" placeholder="Ingresa los SKUs para sincronizar con Falabella (separados por coma o tab). Ejemplo: BVSTBMH23052,XYZ789">{"" if not request.form else request.form.get('skus_falabella', '')}</textarea>
            <button type="submit" name="action" value="actualizar_falabella">Actualizar Stock Falabella</button>
        </form>

        <h2>3. Actualizar Todos los Productos de Falabella</h2>
        <form method="post">
            <button type="submit" name="action" value="actualizar_todos_falabella">Actualizar Todos los SKUs de Falabella</button>
        </form>

        <h2>4. Actualizar Stock de Ciertos SKUs en Walmart</h2>
        <form method="post">
            <textarea name="skus_walmart" placeholder="Ingresa los SKUs para sincronizar con Walmart (separados por coma o tab). Ejemplo: BVSTBMH23052,ABC123">{"" if not request.form else request.form.get('skus_walmart', '')}</textarea>
            <button type="submit" name="action" value="actualizar_walmart">Actualizar Stock Walmart</button>
        </form>

        <h2>5. Actualizar Todos los SKUs de Walmart</h2>
        <form method="post">
            <button type="submit" name="action" value="actualizar_todos_walmart">Actualizar Todos los SKUs de Walmart</button>
        </form>

        {logs_html}
        {res_boletas}
        {res_walmart}
        {res_falabella}
    </body>
    </html>
    """
    return html_content

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
