# mtool
mateors web app necessary 

# How to install?
> go get github.com/mateors/mtool

# Documentation


#### package mtool // import "mateors/lib/mtool"


# VARIABLES

```go
var FuncMap = template.FuncMap{
	"minus":             Mminus,
	"mFormat":           Mformat,
	"toFloat64":         MtoFloat64,
	"toString":          MtoString,
	"toWords":           AmountInWords,
	"plus":              Plus,
	"getFieldValue":     GetFieldValue,
	"sign":              GetSign,
	"fdate":             FormateDate,
	"famount":           AmountFromDebitCredit,
	"getTextMenus":      GetTextMenus,
	"getImageMenus":     GetImageMenus,
	"getMatchedRow":     GetMatchedRow,
	"getLinkRow":        GetLinkRow,
	"getLinkRowByField": GetLinkRowByField,
	"moneyFormat":       MoneyFormat,
	"detailsParser":     LinkDetailsParser,
	"subTotal":          SubTotal,
	"replaceSpace":      ReplaceSpaceBy,
	"toSlice":           StringToSlice,
	"parseDimension":    ParseDimension,
	"uPlus":             Uplus,
	"wishList":          WishList,
	"divideBy":          DivideBy,
}
```

### FuncMap Custom function repository used in template


# FUNCTIONS

- func AmountFromDebitCredit(debit, credit interface{}) (famount string)
    AmountFromDebitCredit to get which one has value not 0

- func AmountInWords(amount interface{}) (inwords string)
    AmountInWords any type amount to string type conversion

- func ArrayDiff(a, b []string) []string
    ArrayDiff Input two string array and get the difference value array

- func ArrayDuplicate(a, b []string) []string
    ArrayDuplicate Get the duplicate value array from two different array

- func ArrayFind(array []string, value string) (bool, int)
    ArrayFind Find a value in_array with its index number

- func ArrayValueExist(array []string, value string) bool
    ArrayValueExist Make sure a value exist in_array or not

- func Bar(a, b, c int)
    Bar test func

- func BrowserInfo(userAgent, battery string) map[string]string
    BrowserInfo parse useragent to map

- func BrowserInfo2(userAgent string) map[string]string
    BrowserInfo2 parse useragent to map

- func Call(m map[string]interface{}, name string, params ...interface{}) (result []reflect.Value, err error)
    Call advance func used in

- func CheckError(formData url.Values, db *sql.DB) string
    CheckError error checklist for signup || check Multiple Condition

- func CheckFileOrFolderExist(dirName string) bool
    CheckFileOrFolderExist takes one argument

- func CheckMultipleConditionTrue(formData url.Values, funcsMap map[string]interface{}, db *mcb.DB) string
    CheckMultipleConditionTrue this func is used for checking multiple
    conditions valid or ERROR

- func CleanText(example string) string
    CleanText takes any string containing any character and return Alphanumeric

- func Convert(number int) string
    Convert converts number into the words representation.

- func ConvertAnd(number int) string
    ConvertAnd converts number into the words representation with " and " added
    between number groups.

- func DateTimeParser(inputDateTime, inputFormat, outputFormat string) (datetime string)
    DateTimeParser datetime parser according to your format

- func DivideBy(a, b interface{}) float64
    DivideBy to division on golang html template

- func ErrorInSlice(slice []string, val string) (int, bool)
    ErrorInSlice to detect error in a string

- func Foo()
    Foo test func

- func FormateDate(date string) (fdate string)
    FormateDate date formatter

- func GenerateBlockNumber() (blockNumber string)
    GenerateBlockNumber unique hexa code

- func GenerateDocNumber(prefix string) (docNumber string)
    GenerateDocNumber to Generate random unique document number

- func GenerateLedgerNumber(prefix, suffix string) (ledgerNumber string)
    GenerateLedgerNumber for accounting voucher

- func GenerateVisitorSession() string
    GenerateVisitorSession using uuid

- func GetFieldValue(tableRows []map[string]interface{}, fieldName, findMyName string) (sRow map[string]interface{})
    GetFieldValue to get any field value

- func GetImageMenus(tableRows []map[string]interface{}, menuID string) map[string]interface{}
    GetImageMenus for link create purpose

- func GetLinkRow(tableRows []map[string]interface{}, imenuID string) (sRow []map[string]interface{})
    GetLinkRow getMatchedRow for go template

- func GetLinkRowByField(tableRows []map[string]interface{}, fieldName, menuID string) (sRow []map[string]interface{})
    GetLinkRowByField for template page

- func GetMatchedRow(tableRows []map[string]interface{}, fieldName, matchValue string) (sRow []map[string]interface{})
    GetMatchedRow for golang html template

- func GetSign(voucherName string) (sign string)
    GetSign Get a sign looking at voucher_name, used in transaction

- func GetTextMenus(tableRows []map[string]interface{}, menuID string) map[string]interface{}
    GetTextMenus for text link

- func IPAddress(RemoteAddr string) (ipaddress string)
    IPAddress [::1] to fresh ip

- func LinkDetailsParser(data string) map[string]string
    LinkDetailsParser link string to map

- func Mformat(a interface{}) string
    Mformat Custom function for template. Takes an input (Any type including
    int,float64,string) Return two decimal digit after the point/precision

- func Mminus(a, b interface{}) float64
    Mminus Custom function for template, Takes two input and return result after
    subtraction

- func MoneyFormat(amount interface{}) string
    MoneyFormat format any number to money format, comma separated

- func MtoFloat64(a interface{}) float64
    MtoFloat64 Custom function for template. Takes an input (Any type including
    int,float64,string) Convert it to float64 and return

- func MtoString(a interface{}) string
    MtoString Custom function for template, Takes one input of any formate and
    convert it to string

- func ParseDimension(text, separator string) map[string]string
    ParseDimension for samsung/FDL company mobile handset only

- func Plus(a, b interface{}) float64
    Plus to Add two input in golang html template

- func ReadUserIP(r *http.Request) string
    ReadUserIP read ip from http pointer to request

- func RegExFindMatch(pattern, data string) (match []string)
    RegExFindMatch find pattern in data string

- func RemoveFromSlice(s []string, i int) []string
    RemoveFromSlice Remove an item from a slice

- func RemoveFromSliceByValue(s []string, value string) []string
    RemoveFromSliceByValue Remove an item from a slice

- func ReplaceSpaceBy(productName, replaceby string) (formattedName string)
    ReplaceSpaceBy remove space by any given char

- func RequestURLtoPage(requestURI string) (pageName, query string)
    RequestURLtoPage r.RequestURI to path and query string

- func ReturnIndexByValue(s []string, val string) (index int)
    ReturnIndexByValue to Get index number by its value from a slice

- func SQLNullString(s interface{}) sql.NullString
    SQLNullString for sql null char

- func StartEndDate(dateTime, layout string) (startDate, endDate string)
    StartEndDate takes two argument, both are string, dateTime="", layout :=
    "2006-01-02 03:04:05"

- func StringToSlice(text, separator string) (slice []string)
    StringToSlice create a slice using separator

- func SubTotal(data []map[string]interface{}) float64
    SubTotal calculate total of a map

- func Sum(nums ...float64) (total float64)
    Sum input as many number as wish, get all number summation ex:
    10.50,20.03,50.25 or slice ending with three dots[slice...]->
    tool.Sum(aSlice...)

- func TimeStampToDate(timeStamp string) (dateFormated string)
    TimeStampToDate formatted date

- func Uplus(nums ...interface{}) string
    Uplus to add multiple values

- func WishList(productID string, wisthList []map[string]interface{}) bool
    WishList check if product_id exist in whishlist