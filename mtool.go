package mtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/avct/uasurfer"
	"github.com/mateors/money"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

//ToString take one argument of any dataType and convert into string
func ToString(data interface{}) string {

	return fmt.Sprintf("%v", data)

}

//TimeNow current system time mysql datetime format
//2006-01-02 15:04:05 = 4digitYear-2digitMonth-2digitDate 24HourFormatHour:minute:second
func TimeNow() string {
	t1 := time.Now()
	createDate := t1.Format("2006-01-02 15:04:05")
	return createDate
}

//TimeNowFormatted "2006-01-02 15:04:05"
//Any format you wish as an output
func TimeNowFormatted(timeFormat string) string {
	t1 := time.Now()
	createDate := t1.Format(timeFormat)
	return createDate
}

//GetVarType any variable to its underlysing data type
func GetVarType(myvar interface{}) string {

	varType := reflect.TypeOf(myvar).Kind().String()

	return varType
}

//GetStructName get struct to its name
func GetStructName(myvar interface{}) string {

	var structName string
	valueOf := reflect.ValueOf(myvar)

	if valueOf.Type().Kind() == reflect.Ptr {
		structName = reflect.Indirect(valueOf).Type().Name()
	} else {
		structName = valueOf.Type().Name()
	}
	return structName
}

//StructToFieldsType get struct to its field_name and data type
func StructToFieldsType(structRef interface{}) map[string]string {

	oMap := make(map[string]string, 0)
	iVal := reflect.ValueOf(structRef).Elem()
	typ := iVal.Type()
	for i := 0; i < iVal.NumField(); i++ {

		f := iVal.Field(i)
		tag := typ.Field(i).Tag.Get("json")
		vtype := f.Kind().String()
		if _, isExist := oMap[tag]; isExist == false {
			oMap[tag] = vtype
		}
	}
	return oMap
}

//StructToFields structToFields
func StructToFields(structRef interface{}) []string {

	cols := make([]string, 0)
	iVal := reflect.ValueOf(structRef).Elem()
	typ := iVal.Type()
	for i := 0; i < iVal.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		cols = append(cols, tag)
	}
	return cols
}

//HashCompare compare plaintext password with hash text
func HashCompare(password, hashpassword string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hashpassword), []byte(password))
	if err != nil {
		return false
	}

	return true
}

//HashBcrypt Generate string to hash
func HashBcrypt(password string) (hash string) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		hash = err.Error()
		return
	}
	hash = string(bytes)
	return
}

//EncodeStr ------------
func EncodeStr(text, password string) (hexcode string) {

	ciphertext := encrypt([]byte(text), password)
	hexcode = fmt.Sprintf("%x", ciphertext)
	return
}

//DecodeStr ...
func DecodeStr(hexcode, password string) (plaintext string) {

	data, err := hex.DecodeString(hexcode)
	if err != nil {
		panic(err)
	}
	byteStr := decrypt(data, password)
	plaintext = fmt.Sprintf("%s", byteStr)

	return
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {

	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {

	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

//ValueType ...
func ValueType(v interface{}) string {
	xType := reflect.ValueOf(v).Kind().String()
	return xType
}

//GetMapValue safer way to get value from map
func GetMapValue(mapData map[string]string, key string) (val string) {

	if v, isOk := mapData[key]; isOk {
		val = v
	}
	return
}

//StringToMap comma separated string to map
//input=access_name:student,cid:1,login_id:2
//output=map[access_name:student cid:1 login_id:2]
func StringToMap(output string) map[string]string {

	sMap := make(map[string]string, 0)
	slice := strings.Split(output, ",")

	for _, val := range slice {
		slc := strings.Split(val, ":")
		if len(slc) == 2 {
			sMap[slc[0]] = slc[1]
		}
	}
	return sMap
}

//MapToString map to string comma separated
//input=map[access_name:student cid:1 login_id:2]
//output=access_name:student,cid:1,login_id:2
func MapToString(sRow map[string]string) string {

	var output string
	for key, val := range sRow {
		str := fmt.Sprintf("%s:%v", key, val)
		output += str + ","
	}
	output = strings.TrimRight(output, ",")
	return output
}

//ReadUserIP read ip from http pointer to request
func ReadUserIP(r *http.Request) string {

	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress != "" {
		return IPAddress
	}

	IPAddress = r.FormValue("ip") //r.RemoteAddr
	if IPAddress != "" {
		return IPAddress
	}

	IPAddress = r.Header.Get("X-Forwarded-For")
	if IPAddress != "" {
		return IPAddress
	}

	IPAddress = r.RemoteAddr
	if IPAddress != "" {
		//fmt.Println("IP Detect using r.RemoteAddr::", IPAddress, r.Referer(), xforward)
	}

	if IPAddress == "" {
		fmt.Println("IP Detect using ReadUserIP:: NO IP FOUND", r.Referer())
	}

	return IPAddress
}

//StartEndDate takes two argument, both are string, dateTime="", layout := "2006-01-02 03:04:05"
func StartEndDate(dateTime, layout string) (startDate, endDate string) {

	//layout := "2006-01-02 03:04:05"
	var dtime time.Time

	if dateTime == "" {
		dtime = time.Now()

	} else {
		dtime, _ = time.Parse(layout, dateTime)
	}

	bom := dtime.AddDate(0, 0, -dtime.Day()+1)
	eom := dtime.AddDate(0, 1, -dtime.Day())

	startDate = bom.Format(layout)
	endDate = eom.Format(layout)

	return
}

//GenerateVisitorSession using uuid
func GenerateVisitorSession() string {

	v1, _ := uuid.NewV1()
	v1string := fmt.Sprintf("%v", v1)

	return strings.ToUpper(v1string)
}

func formatCommas(num int) string {

	str := fmt.Sprintf("%d", num)
	re := regexp.MustCompile("(\\d+)(\\d{3})")
	for n := ""; n != str; {
		n = str
		str = re.ReplaceAllString(str, "$1,$2")
	}
	return str
}

//CleanText takes any string containing any character and return Alphanumeric
func CleanText(example string) string {

	reg, err := regexp.Compile("[^a-zA-Z0-9 ]+")
	if err != nil {
		log.Fatal(err)
	}
	processedString := reg.ReplaceAllString(example, "")

	return processedString
}

//SQLNullString for sql null char
func SQLNullString(s interface{}) sql.NullString {

	d := fmt.Sprintf("%v", s)
	if len(d) == 0 {
		return sql.NullString{}
	}

	return sql.NullString{
		String: d,
		Valid:  true,
	}
}

//BrowserInfo2 parse useragent to map
func BrowserInfo2(userAgent string) map[string]string {

	info := make(map[string]string, 0)
	ua := uasurfer.Parse(userAgent)
	device := ua.DeviceType.StringTrimPrefix()

	info["device"] = device
	info["browser_version"] = fmt.Sprintf("%s %v.%v.%v", ua.Browser.Name.StringTrimPrefix(), ua.Browser.Version.Major, ua.Browser.Version.Minor, ua.Browser.Version.Patch)
	info["os_version"] = fmt.Sprintf("%s %v", ua.OS.Name.StringTrimPrefix(), ua.OS.Version.Major)
	info["platform"] = ua.OS.Platform.StringTrimPrefix()

	return info
}

//BrowserInfo parse useragent to map
func BrowserInfo(userAgent, battery string) map[string]string {

	info := make(map[string]string, 0)

	//myUA := "User-agent header: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"
	// Parse() returns all attributes, including returning the full UA string last
	ua := uasurfer.Parse(userAgent)
	device := ua.DeviceType.StringTrimPrefix()

	if battery == "true" {
		device = "Laptop"

	} else if battery == "false" && device == "Computer" {
		device = "Desktop"

	} else {
		//device=device
	}

	info["device"] = device
	info["browser_version"] = fmt.Sprintf("%s %v.%v.%v", ua.Browser.Name.StringTrimPrefix(), ua.Browser.Version.Major, ua.Browser.Version.Minor, ua.Browser.Version.Patch)
	info["os_version"] = fmt.Sprintf("%s %v", ua.OS.Name.StringTrimPrefix(), ua.OS.Version.Major)
	info["platform"] = ua.OS.Platform.StringTrimPrefix()

	return info

}

//CheckFileOrFolderExist takes one argument
func CheckFileOrFolderExist(dirName string) bool {

	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		return false
	}
	return true
}

//RegExFindMatch find pattern in data string
func RegExFindMatch(pattern, data string) (match []string) {

	var myExp = regexp.MustCompile(pattern)
	match = myExp.FindStringSubmatch(data)

	return
}

//IPAddress [::1] to fresh ip
func IPAddress(RemoteAddr string) (ipaddress string) {

	matchA := RegExFindMatch(`^\[(.*)\]:(\d+)$`, RemoteAddr)
	if len(matchA) == 3 {
		ipaddress = matchA[1]
	}
	return
}

//TimeStampToDate formatted date
func TimeStampToDate(timeStamp string) (dateFormated string) {

	i, err := strconv.ParseInt(timeStamp, 10, 64)
	if err != nil {
		fmt.Println("ERROR", err.Error())
		return
	}

	tm := time.Unix(i, 0)
	dateFormated = tm.Format("2006-01-02 15:04:05")

	return
}

//ArrayValueExist Make sure a value exist in_array or not
func ArrayValueExist(array []string, value string) bool {

	indx := ReturnIndexByValue(array, value)
	//fmt.Println(indx)
	if indx == -1 {
		//fmt.Println("NOT FOUND")
		return false
	}

	return true
}

//ArrayFind Find a value in_array with its index number
func ArrayFind(array []string, value string) (bool, int) {

	indx := ReturnIndexByValue(array, value)
	if indx == -1 {
		fmt.Println("NOT FOUND")
		return false, -1
	}

	return true, indx
}

//ArrayDiff Input two string array and get the difference value array
func ArrayDiff(a, b []string) []string {
	temp := map[string]int{}
	for _, s := range a {
		temp[s]++
	}
	for _, s := range b {
		temp[s]--
	}

	var result []string
	for s, v := range temp {
		if v != 0 {
			result = append(result, s)
		}
	}
	return result
}

//ArrayDuplicate Get the duplicate value array from two different array
func ArrayDuplicate(a, b []string) []string {
	temp := map[string]int{}
	for _, s := range a {
		temp[s]++
	}
	for _, s := range b {
		temp[s]--
	}

	var result []string
	for s, v := range temp {
		if v == 0 {
			result = append(result, s)
		}
	}
	return result
}

//FuncMap Custom function repository used in template
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

//WishList check if product_id exist in whishlist
func WishList(productID string, wisthList []map[string]interface{}) bool {

	for _, row := range wisthList {

		if pid, ok := row["product_id"]; ok {
			if pid.(string) == productID {

				return true
			}
		}
	}

	return false
}

//ParseDimension for samsung/FDL company mobile handset only
func ParseDimension(text, separator string) map[string]string {

	slice := strings.Split(text, separator)
	dimension := make(map[string]string, 0)

	for i, v := range slice {
		if i == 0 {
			dimension["width"] = v
		} else if i == 1 {
			dimension["height"] = v
		} else if i == 2 {
			dimension["thickness"] = v
		}
	}

	return dimension
}

//StringToSlice create a slice using separator
func StringToSlice(text, separator string) (slice []string) {

	slice = strings.Split(text, separator) //separator=","

	return

}

//ReplaceSpaceBy remove space by any given char
func ReplaceSpaceBy(productName, replaceby string) (formattedName string) {

	//fmt.Println("product_name-2:", product_name)
	formattedName = strings.Replace(productName, " ", "-", -1)

	return

}

//SubTotal calculate total of a map
func SubTotal(data []map[string]interface{}) float64 {

	var total float64
	for _, row := range data {
		payableAmount, _ := strconv.ParseFloat(row["payable_amount"].(string), 64)
		total += payableAmount
	}

	return total
}

func getParams(regEx, url string) (paramsMap map[string]string) {

	var compRegEx = regexp.MustCompile(regEx)
	match := compRegEx.FindStringSubmatch(url)

	paramsMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	return
}

//LinkDetailsParser link string to map
func LinkDetailsParser(data string) map[string]string {

	//boldtxt:And more,off_upto:50%
	//boldtxt:Arrives,from:990
	//fmt.Println(data, len(data))

	//boldtxt:And more,off_upto:50
	// pattern := []string{`(?P<name>.*):,(?P<off_upto>:.*)`, `^boldtxt:(.*),from:(\d+),sign:(.*)`}
	// for _, ptxt := range pattern {
	// 	match = getParams(ptxt, data)
	// 	if len(match) > 0 {
	// 		return match
	// 	}
	// }

	match := make(map[string]string, 0)
	//boldtxt:And more,off_upto:50%,name:discount
	sA := strings.Split(data, ",")
	for _, v := range sA {
		vA := strings.Split(v, ":")
		key := vA[0]
		val := vA[1]
		_, keyExist := match[key]
		if keyExist == false {
			match[key] = val
		}
	}
	return match

}

//MoneyFormat format any number to money format, comma separated
func MoneyFormat(amount interface{}) string {

	//namount := fmt.Sprintf("%.f", amount)
	fmoney := money.CommaSeparatedMoneyFormat(amount)
	return strings.TrimRight(strings.TrimRight(fmoney, "0"), ".")

}

//GetLinkRowByField for template page
func GetLinkRowByField(tableRows []map[string]interface{}, fieldName, menuID string) (sRow []map[string]interface{}) {

	for _, rMap := range tableRows {

		fieldVal := rMap[fieldName].(string) //product_id
		linkID := rMap["link_id"].(string)

		if fieldVal == menuID && len(linkID) > 0 {
			//sRow = rMap
			sRow = append(sRow, rMap)
			//fmt.Println(fvalue, "MATCH FOUND", rMap)
		}

	}

	return sRow
}

//GetLinkRow getMatchedRow for go template
func GetLinkRow(tableRows []map[string]interface{}, imenuID string) (sRow []map[string]interface{}) {

	for _, rMap := range tableRows {

		menuID := rMap["menu_id"].(string) //product_id
		linkID := rMap["link_id"].(string)

		if menuID == imenuID && len(linkID) > 0 {
			sRow = append(sRow, rMap)
		}
	}

	return sRow
}

//GetMatchedRow for golang html template
func GetMatchedRow(tableRows []map[string]interface{}, fieldName, matchValue string) (sRow []map[string]interface{}) {

	for _, rMap := range tableRows {

		fvalue := rMap[fieldName].(string) //product_id

		if fvalue == matchValue {
			//sRow = rMap
			sRow = append(sRow, rMap)
			//fmt.Println(fvalue, "MATCH FOUND", rMap)
		}
	}
	return sRow
}

//GetImageMenus for link create purpose
func GetImageMenus(tableRows []map[string]interface{}, menuID string) map[string]interface{} {

	data := make(map[string]interface{}, 0)

	for _, rMap := range tableRows {

		fvalue := rMap["parent"].(string) //product_id
		image := rMap["image"].(string)

		if fvalue == menuID && image != "" {

			linkURL := rMap["link_url"].(string)
			//menu_id := rMap["menu_id"]
			_, ok := data[linkURL]
			if ok == false {
				data[linkURL] = image
			}

			//fmt.Println(fvalue, "IMAGE FOUND", image)
		}

	}

	return data
}

//GetTextMenus for text link
func GetTextMenus(tableRows []map[string]interface{}, menuID string) map[string]interface{} {

	data := make(map[string]interface{}, 0)

	for _, rMap := range tableRows {

		fvalue := rMap["parent"].(string) //product_id
		image := rMap["image"].(string)

		if fvalue == menuID && image == "" {
			//sRow = rMap
			//sRow = append(sRow, rMap)
			menuName := rMap["menu_name"].(string)
			menuID := rMap["menu_id"]
			_, ok := data[menuName]
			if ok == false {
				data[menuName] = menuID
			}
			//fmt.Println(fvalue, "MATCH FOUND", data, image)
		}

	}

	return data
}

//AmountFromDebitCredit to get which one has value not 0
func AmountFromDebitCredit(debit, credit interface{}) (famount string) {

	sdebit := fmt.Sprintf("%v", debit)
	scredit := fmt.Sprintf("%v", credit)

	if sdebit == "" {
		famount = scredit
	} else if scredit == "" {
		famount = sdebit
	}

	return
}

//FormateDate date formatter
func FormateDate(date string) (fdate string) {

	inputFormat := "2006-01-02"
	outputFormat := "02/01/06"
	fdate = DateTimeParser(date, inputFormat, outputFormat)

	return
}

//GetSign Get a sign looking at voucher_name, used in transaction
func GetSign(voucherName string) (sign string) {

	plusAray := []string{"Balance Add", "Add", "Add Balance"}
	minusAray := []string{"Balance Transfer", "Transfer"}

	_, inPlus := stringInSlice(plusAray, voucherName)
	_, inMinus := stringInSlice(minusAray, voucherName)

	if inPlus == true {
		sign = "+"
	} else if inMinus == true {
		sign = "-"
	}

	return
}

//GetFieldValue to get any field value
func GetFieldValue(tableRows []map[string]interface{}, fieldName, findMyName string) (sRow map[string]interface{}) {

	//fmt.Println("ROWS: ", tableRows)
	for _, rMap := range tableRows {

		fvalue := rMap[fieldName].(string) //product_id
		if fvalue == findMyName {
			sRow = rMap
			//fmt.Println("MATCH FOUND", rMap)
			return
		}

	}

	return nil

}

//Plus to Add two input in golang html template
func Plus(a, b interface{}) float64 {

	astr := fmt.Sprintf("%v", a)
	bstr := fmt.Sprintf("%v", b)

	aflt, _ := strconv.ParseFloat(astr, 64)
	bflt, _ := strconv.ParseFloat(bstr, 64)

	return aflt + bflt
}

//DivideBy to division on golang html template
func DivideBy(a, b interface{}) float64 {

	astr := fmt.Sprintf("%v", a)
	bstr := fmt.Sprintf("%v", b)

	aflt, _ := strconv.ParseFloat(astr, 64)
	bflt, _ := strconv.ParseFloat(bstr, 64)

	return aflt / bflt
}

//Uplus to add multiple values
func Uplus(nums ...interface{}) string {

	total := 0
	for _, num := range nums {
		numstr := fmt.Sprintf("%v", num)
		number, _ := strconv.Atoi(numstr)
		total += number
	}

	return fmt.Sprintf("%v", total)
}

//AmountInWords any type amount to string type conversion
func AmountInWords(amount interface{}) (inwords string) {

	astr := fmt.Sprintf("%v", amount)
	aflt, _ := strconv.ParseFloat(astr, 64)
	inwords = strings.Title(ConvertAnd(int(aflt)))
	return
}

//MtoString Custom function for template,
//Takes one input of any formate and convert it to string
func MtoString(a interface{}) string {

	astr := fmt.Sprintf("%v", a) //interface to string
	//fmt.Printf("\n\na: %v\n", astr)
	return astr
}

//Mminus Custom function for template,
//Takes two input and return result after subtraction
func Mminus(a, b interface{}) float64 {

	astr := fmt.Sprintf("%v", a) //interface to string
	bstr := fmt.Sprintf("%v", b) //interface to string

	x, _ := strconv.ParseFloat(astr, 64)
	y, _ := strconv.ParseFloat(bstr, 64)
	return x - y
}

//Mformat Custom function for template.
//Takes an input (Any type including int,float64,string)
//Return two decimal digit after the point/precision
func Mformat(a interface{}) string {

	astr := fmt.Sprintf("%v", a) //interface to string
	aflt, _ := strconv.ParseFloat(astr, 64)
	afmt := fmt.Sprintf("%.2f", aflt)
	return afmt
}

//MtoFloat64 Custom function for template.
//Takes an input (Any type including int,float64,string)
//Convert it to float64 and return
func MtoFloat64(a interface{}) float64 {

	astr := fmt.Sprintf("%v", a)
	vflt, _ := strconv.ParseFloat(astr, 64)
	return vflt
}

//RequestURLtoPage r.RequestURI to path and query string
func RequestURLtoPage(requestURI string) (pageName, query string) {

	purl, _ := url.Parse(requestURI)
	path := strings.TrimLeft(purl.Path, "/")
	pageName = strings.Replace(path, "/", "_", -1)
	query = purl.RawQuery

	return
}

//GenerateBlockNumber unique hexa code
func GenerateBlockNumber() (blockNumber string) {

	v1, _ := uuid.NewV1()
	v1string := fmt.Sprintf("%x", v1)
	blockNumber = strings.ToUpper(v1string[0:12])

	return
}

//GenerateLedgerNumber for accounting voucher
func GenerateLedgerNumber(prefix, suffix string) (ledgerNumber string) {

	ledgerNumber = fmt.Sprintf("%v%08s", prefix, suffix)
	return
}

//GenerateDocNumber to Generate random unique document number
func GenerateDocNumber(prefix string) (docNumber string) {

	v1, _ := uuid.NewV1()
	v1string := fmt.Sprintf("%s", v1)
	randomValue := strings.ToUpper(v1string[0:8])
	docNumber = fmt.Sprintf("%v%v", prefix, randomValue)

	return
}

//DateTimeParser datetime parser according to your format
func DateTimeParser(inputDateTime, inputFormat, outputFormat string) (datetime string) {

	ptime, _ := time.Parse(inputFormat, inputDateTime)
	datetime = ptime.Format(outputFormat)
	return datetime
}

//Sum input as many number as wish, get all number summation ex: 10.50,20.03,50.25
//or slice ending with three dots[slice...]-> tool.Sum(aSlice...)
func Sum(nums ...float64) (total float64) {

	for _, num := range nums {
		total += num
	}
	return
}

//ReturnIndexByValue to Get index number by its value from a slice
func ReturnIndexByValue(s []string, val string) (index int) {

	for index, v := range s {
		if v == val {
			return index
		}
	}
	return -1
}

//RemoveFromSliceByValue Remove an item from a slice
func RemoveFromSliceByValue(s []string, value string) []string {

	index := ReturnIndexByValue(s, value)
	na := RemoveFromSlice(s, index)
	return na
}

//RemoveFromSlice Remove an item from a slice
func RemoveFromSlice(s []string, i int) []string {

	//a := []string{"A", "B", "C", "D", "E"}
	//i := 2

	// Remove the element at index i from a.
	//a[i] = a[len(a)-1] // Copy last element to index i.
	//A, B, E, D, -
	//0-3=A,B,E,D
	//a[len(a)-1] = ""   // Erase last element (write zero value).
	//a = a[:len(a)-1]   // Truncate slice.
	//s[i] = s[len(s)-1]
	//s[:len(s)-1]
	a := append(s[:i], s[i+1:]...)
	return a

}

//ErrorInSlice to detect error in a string
func ErrorInSlice(slice []string, val string) (int, bool) {

	for i, item := range slice {

		//strings.Contains(item, "ERROR")
		if strings.Contains(item, val) == true {
			return i, true
		}
	}
	return -1, false
}

func stringInSlice(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

//Call advance func used in
func Call(m map[string]interface{}, name string, params ...interface{}) (result []reflect.Value, err error) {

	f := reflect.ValueOf(m[name])
	if len(params) != f.Type().NumIn() {
		err = errors.New("the number of params is not adapted")
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}

	result = f.Call(in)
	return

}

// how many digit's groups to process
const groupsNumber int = 4

var _smallNumbers = []string{
	"zero", "one", "two", "three", "four",
	"five", "six", "seven", "eight", "nine",
	"ten", "eleven", "twelve", "thirteen", "fourteen",
	"fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
}
var _tens = []string{
	"", "", "twenty", "thirty", "forty", "fifty",
	"sixty", "seventy", "eighty", "ninety",
}
var _scaleNumbers = []string{
	"", "thousand", "million", "billion",
}

type digitGroup int

// Convert converts number into the words representation.
func Convert(number int) string {
	return convert(number, false)
}

// ConvertAnd converts number into the words representation
// with " and " added between number groups.
func ConvertAnd(number int) string {
	return convert(number, true)
}

func convert(number int, useAnd bool) string {
	// Zero rule
	if number == 0 {
		return _smallNumbers[0]
	}

	// Divide into three-digits group
	var groups [groupsNumber]digitGroup
	positive := math.Abs(float64(number))

	// Form three-digit groups
	for i := 0; i < groupsNumber; i++ {
		groups[i] = digitGroup(math.Mod(positive, 1000))
		positive /= 1000
	}

	var textGroup [groupsNumber]string
	for i := 0; i < groupsNumber; i++ {
		textGroup[i] = digitGroup2Text(groups[i], useAnd)
	}
	combined := textGroup[0]
	and := useAnd && (groups[0] > 0 && groups[0] < 100)

	for i := 1; i < groupsNumber; i++ {
		if groups[i] != 0 {
			prefix := textGroup[i] + " " + _scaleNumbers[i]

			if len(combined) != 0 {
				prefix += separator(and)
			}

			and = false

			combined = prefix + combined
		}
	}

	if number < 0 {
		combined = "minus " + combined
	}

	return combined
}

func intMod(x, y int) int {
	return int(math.Mod(float64(x), float64(y)))
}

func digitGroup2Text(group digitGroup, useAnd bool) (ret string) {
	hundreds := group / 100
	tensUnits := intMod(int(group), 100)

	if hundreds != 0 {
		ret += _smallNumbers[hundreds] + " hundred"

		if tensUnits != 0 {
			ret += separator(useAnd)
		}
	}

	tens := tensUnits / 10
	units := intMod(tensUnits, 10)

	if tens >= 2 {
		ret += _tens[tens]

		if units != 0 {
			ret += "-" + _smallNumbers[units]
		}
	} else if tensUnits != 0 {
		ret += _smallNumbers[tensUnits]
	}

	return
}

// separator returns proper separator string between number groups.
func separator(useAnd bool) string {
	if useAnd {
		return " and "
	}
	return " "
}
