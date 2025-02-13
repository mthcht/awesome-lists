rule Trojan_Win64_Glupteba_B_2147794933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Glupteba.B!MTB"
        threat_id = "2147794933"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AAEGHwMLABwKARwCAAYJBgYKAg==" ascii //weight: 1
        $x_1_2 = "Set-ExecutionPolicy RemoteSigned -Scope Process -Force -Confirm:$false;$PSDefaultParameterValues" ascii //weight: 1
        $x_1_3 = "YldHHHdLVFFGRVtcX2JcXVtQSBJhVF9cRVdgWFVdVFYTHGFQXkJWEWJBXlFWQkETHHRcQ1FWER9wXlxVWEBeCxZVU" ascii //weight: 1
        $x_1_4 = "ER1HQ1NdQlRWQxIRe3gREQ==" ascii //weight: 1
        $x_1_5 = "WUZHQUEJHh1ERkUdV1NQVFBcXlkdUl1eHkFHQ1dfWl1FH0RcXVZWXFNBHkJcQkZAHgoEAwoCAAECBwULBwoKAE5bRUZDQggcHkV" ascii //weight: 1
        $x_1_6 = "YnF7ZXNgemETHnFBVFNHVBIcYnETfnx/fnV8fxIcZXwT" ascii //weight: 1
        $x_1_7 = "HlETQVtdVhJfXlFSXVpcQkYTHFwTAhINEVxGXRIVEVZWXRI=" ascii //weight: 1
        $x_1_8 = "Z3xwEVRaXVcTX11HEXZcRlxfXlNXVFYTXkATZFxJWEJWVQ==" ascii //weight: 1
        $x_1_9 = "dEBBXkATQkZSQ0ZaX1UTQUBcUlFWQkETGQ==" ascii //weight: 1
        $x_1_10 = "dEBBXkATVV1EX15cUFZaX1UTGQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

