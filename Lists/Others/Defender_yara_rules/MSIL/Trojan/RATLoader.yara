rule Trojan_MSIL_RATLoader_2147780307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RATLoader!MTB"
        threat_id = "2147780307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RATLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.IO.Compression" ascii //weight: 1
        $x_1_2 = "System.Reflection.Emit" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_4 = "System.Text.RegularExpressions" ascii //weight: 1
        $x_1_5 = "System.Threading" ascii //weight: 1
        $x_1_6 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "get_ManagedThreadId" ascii //weight: 1
        $x_1_9 = "WriteAllBytes" ascii //weight: 1
        $x_1_10 = "WriteAllText" ascii //weight: 1
        $x_1_11 = "GetCurrentProcess" ascii //weight: 1
        $x_1_12 = "set_Arguments" ascii //weight: 1
        $x_1_13 = "set_WindowStyle" ascii //weight: 1
        $x_1_14 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_15 = "set_ErrorDialog" ascii //weight: 1
        $x_1_16 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_17 = "GetFileNameWithoutExtension" ascii //weight: 1
        $x_1_18 = "get_MainWindowTitle" ascii //weight: 1
        $x_1_19 = "get_SystemDirectory" ascii //weight: 1
        $x_1_20 = "get_ExecutablePath" ascii //weight: 1
        $x_1_21 = "set_UseShellExecute" ascii //weight: 1
        $x_1_22 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_23 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_24 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_25 = "FromBase64String" ascii //weight: 1
        $x_1_26 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_27 = "set_Key" ascii //weight: 1
        $x_1_28 = "set_IV" ascii //weight: 1
        $x_1_29 = "CreateDecryptor" ascii //weight: 1
        $x_1_30 = "FlushFinalBlock" ascii //weight: 1
        $x_1_31 = "CreateEncryptor" ascii //weight: 1
        $x_1_32 = "ToBase64String" ascii //weight: 1
        $x_1_33 = "get_Y" ascii //weight: 1
        $x_1_34 = "get_X" ascii //weight: 1
        $x_1_35 = "Kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

