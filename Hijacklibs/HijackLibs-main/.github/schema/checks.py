import logging
import sys
import os
log = logging.getLogger(__name__)
log.setLevel("DEBUG")

def check_root(value, rule_obj, path):
    # Filename data
    full_path = None
    for i, args in enumerate(sys.argv):
        if args in ('--data-file', '-d'):
            full_path = sys.argv[i+1]

    if not full_path: raise Exception("Could not find path to YAML file.")

    file_path = os.path.normpath(full_path).split(os.path.sep)
    vendor_type, vendor, filename = file_path[-3:]

    if not filename.endswith('.yml'):
        raise AssertionError("Unexpected file extension, must be '.yml' (case sensitive).")
    if filename.lower() != filename or vendor.lower() != vendor:
        raise AssertionError("File name and file path must be completely lowercase.")
    if not vendor_type in ('microsoft', '3rd_party'):
        raise AssertionError("Unexpected vendor type.")
    if vendor_type == 'microsoft' and vendor not in ('built-in', 'external'):
        raise AssertionError("Unexpected type for Microsoft entry.")

    # YAML-provided data
    entry_name = value.get('Name')
    if entry_name.replace('.dll', '.yml').replace('.ocx', '.yml') != filename:
        raise AssertionError("File name does not match 'Name' field.")
    vendor_name = value.get('Vendor').replace(' ', '')
    if vendor_name.lower() != (vendor if vendor_type == '3rd_party' else vendor_type):
        raise AssertionError("Vendor folder name does not match 'Vendor' field.")

    return not_empty(value, rule_obj, path)

def check_executables(value, rule_obj, path):
    log.debug("value: %s", value)
    log.debug("rule_obj: %s", rule_obj)
    log.debug("path: %s", path)

    if value.get("Type") == "Environment Variable" and not value.get("Variable"):
        raise AssertionError("'Variable' must be specified when 'Type' is set to 'Environment Variable'.")
    if value.get("Type") != "Environment Variable" and value.get("Variable"):
        raise AssertionError("'Variable' must only be specified if 'Type' is set to 'Environment Variable'.")
    if value.get("Variable") and '%' in value.get("Variable"):
        raise AssertionError("'Variable' should contain the Environment Variable name without percentage signs (%).")

    return not_empty(value, rule_obj, path)

def not_empty(value, rule_obj, path):
    log.debug("value: %s", value)
    log.debug("rule_obj: %s", rule_obj)
    log.debug("path: %s", path)
    if isinstance(value, dict):
        empties = [key for key, val in value.items() if not val]
        if empties:
            result = []
            for empty in empties:
                is_required = rule_obj.schema_str['mapping'][empty].get('required', False)

                message = 'Key "{}" cannot be empty; '.format(empty)
                if not is_required:
                    message += 'please remove the entire line'
                else:
                    message += 'is required'
                result.append(message)
            raise AssertionError('\n'.join(result))
    else:
        raise ValueError('Unexpected value type {}'.format(type(value)))
    return True
