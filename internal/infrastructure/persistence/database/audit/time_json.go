package auditstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

var auditTimeType = reflect.TypeOf(time.Time{})

func marshalAuditJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	document, err := decodeAuditDocument(raw)
	if err != nil {
		return nil, err
	}
	document, err = encodeAuditTimes(reflect.ValueOf(value), document, "")
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

func unmarshalAuditJSON(raw []byte, destination any) error {
	document, err := decodeAuditDocument(raw)
	if err != nil {
		return err
	}
	document, err = decodeAuditTimes(document, "")
	if err != nil {
		return err
	}
	normalized, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, destination)
}

func decodeAuditDocument(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	return value, err
}

func encodeAuditTimes(value reflect.Value, document any, name string) (any, error) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return document, nil
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return document, nil
	}
	if value.Type() == auditTimeType {
		instant := value.Interface().(time.Time)
		return instant.UTC().UnixMilli(), nil
	}
	if auditInstantField(name) && value.Kind() == reflect.String {
		text := strings.TrimSpace(value.String())
		if text == "" {
			return int64(0), nil
		}
		instant, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil, fmt.Errorf("audit time field %s is invalid: %w", name, err)
		}
		return instant.UTC().UnixMilli(), nil
	}
	switch value.Kind() {
	case reflect.Map:
		object, ok := document.(map[string]any)
		if !ok || value.Type().Key().Kind() != reflect.String {
			return document, nil
		}
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			child, exists := object[key]
			if !exists {
				continue
			}
			normalized, err := encodeAuditTimes(iterator.Value(), child, key)
			if err != nil {
				return nil, err
			}
			object[key] = normalized
		}
		return object, nil
	case reflect.Struct:
		object, ok := document.(map[string]any)
		if !ok {
			return document, nil
		}
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if field.PkgPath != "" {
				continue
			}
			fieldName := strings.Split(field.Tag.Get("json"), ",")[0]
			if fieldName == "-" {
				continue
			}
			if fieldName == "" {
				fieldName = field.Name
			}
			if child, exists := object[fieldName]; exists {
				normalized, err := encodeAuditTimes(value.Field(index), child, fieldName)
				if err != nil {
					return nil, err
				}
				object[fieldName] = normalized
			}
		}
		return object, nil
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return document, nil
		}
		items, ok := document.([]any)
		if !ok {
			return document, nil
		}
		for index := 0; index < value.Len() && index < len(items); index++ {
			normalized, err := encodeAuditTimes(value.Index(index), items[index], "")
			if err != nil {
				return nil, err
			}
			items[index] = normalized
		}
		return items, nil
	default:
		return document, nil
	}
}

func decodeAuditTimes(document any, name string) (any, error) {
	if auditInstantField(name) {
		number, ok := document.(json.Number)
		if !ok {
			return nil, fmt.Errorf("stored audit time field %s must be a Unix-millisecond number", name)
		}
		value, err := number.Int64()
		if err != nil {
			return nil, fmt.Errorf("stored audit time field %s must be an integer: %w", name, err)
		}
		return value, nil
	}
	switch value := document.(type) {
	case map[string]any:
		for key, child := range value {
			normalized, err := decodeAuditTimes(child, key)
			if err != nil {
				return nil, err
			}
			value[key] = normalized
		}
	case []any:
		for index := range value {
			normalized, err := decodeAuditTimes(value[index], "")
			if err != nil {
				return nil, err
			}
			value[index] = normalized
		}
	}
	return document, nil
}

func auditInstantField(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	return strings.HasSuffix(name, "_at") || strings.HasSuffix(name, "_timestamp") || name == "timestamp" || name == "scheduled_for" || name == "not_before" || name == "lease_until" || name == "deliver_after"
}
