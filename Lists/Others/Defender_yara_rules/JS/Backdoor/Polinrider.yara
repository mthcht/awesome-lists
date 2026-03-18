rule Backdoor_JS_Polinrider_A_2147965048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:JS/Polinrider.A"
        threat_id = "2147965048"
        type = "Backdoor"
        platform = "JS: JavaScript scripts"
        family = "Polinrider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://fullnode.mainnet.aptoslabs.com/v1/accounts/" ascii //weight: 1
        $x_1_2 = "/transactions?only_confirmed=true&only_from=true&limit=1" ascii //weight: 1
        $x_1_3 = "https://api.trongrid.io/v1/accounts/" ascii //weight: 1
        $x_1_4 = "bsc-rpc.publicnode.com" ascii //weight: 1
        $x_1_5 = "bsc-dataseed.binance.org" ascii //weight: 1
        $x_1_6 = "eth_getTransactionByHash" ascii //weight: 1
        $x_1_7 = "={hostname:" ascii //weight: 1
        $x_1_8 = "({jsonrpc:" ascii //weight: 1
        $x_1_9 = ",id:1});const" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

