rule Backdoor_Linux_PoshPyReShell_A_2147767728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PoshPyReShell.A!!PoshPyReShell.A"
        threat_id = "2147767728"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PoshPyReShell"
        severity = "Critical"
        info = "PoshPyReShell: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if pykey in b and pyhash == s.hexdigest() and cstr < kdn: exec(b)" ascii //weight: 1
        $x_1_2 = "un=pwd.getpwuid(os.getuid())[ 0 ];pid=os.getpid()" ascii //weight: 1
        $x_1_3 = "is64=sys.maxsize > 2**32;" ascii //weight: 1
        $x_1_4 = "encsid=encrypt(key, '%s;%s;%s;%s;%s;%s' % (un,hn,hn,arch,pid,urlid))" ascii //weight: 1
        $x_1_5 = "decrypt(key, html).rstrip('\\0');exec(base64.b64decode(x))" ascii //weight: 1
        $x_1_6 = "def encrypt(key, data, gzip=False):" ascii //weight: 1
        $x_1_7 = "def get_encryption(key, iv):" ascii //weight: 1
        $x_1_8 = "def decrypt(key, data):" ascii //weight: 1
        $x_1_9 = "tmp/%s.sh\" % (uuid.uuid4().hex)" ascii //weight: 1
        $x_1_10 = "%s/%s_psh.sh\" % (dircontent, uuid.uuid4().hex)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_PoshPyReShell_B_2147768300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PoshPyReShell.B!!PoshPyReShell.B"
        threat_id = "2147768300"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PoshPyReShell"
        severity = "Critical"
        info = "PoshPyReShell: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pykey=" ascii //weight: 1
        $x_1_2 = "pyhash=" ascii //weight: 1
        $x_1_3 = "serverclean" ascii //weight: 1
        $x_1_4 = "aWIyLnVybG9wZW4ocik7aHRtbD1yZXMucmVhZCgpO3g9ZGVjcnlwdChrZXksIGh0bWwpLnJzdHJpcCgnXDAnKTtleGVjKGJhc2U2NC5iNjRkZWNvZGUoeCkpCg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_PoshPyReShell_C_2147768412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PoshPyReShell.C!!PoshPyReShell.C"
        threat_id = "2147768412"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PoshPyReShell"
        severity = "Critical"
        info = "PoshPyReShell: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wn/X6tlSe52Re3WXZl3My1mw03KEBcCq/qW/e/Nschk" ascii //weight: 1
        $x_1_2 = "kdn=time.strptime(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

