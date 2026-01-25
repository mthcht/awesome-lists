rule Backdoor_Win32_MQTTClient_A_2147961649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/MQTTClient.A"
        threat_id = "2147961649"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "MQTTClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MQTTClient" ascii //weight: 1
        $x_1_2 = "v += (byte & 0x7F) * m" ascii //weight: 1
        $x_1_3 = "make_connect(client_id:" ascii //weight: 1
        $x_1_4 = "make_plugin_data(plugin_id:" ascii //weight: 1
        $x_1_5 = "plugins = json.loads(payload.decode())" ascii //weight: 1
        $x_1_6 = "\\'SendDataToServer\\': lambda data, pid=plugin_id: self._send_response(pid, data)" ascii //weight: 1
        $x_1_7 = "payload = json.dumps({\\'plugin\\': plugin_id, \\'action\\': action, \\'data\\': data}).encode()" ascii //weight: 1
        $x_1_8 = "CONNECT, CONNACK, PINGREQ, PINGRESP, DISCONNECT, PLUGIN_DATA, PLUGIN_CODE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

