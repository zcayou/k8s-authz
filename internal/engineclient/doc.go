// Package engineclient reads what one selected OPA engine serves, and replaces
// its state document and its conditions module, over its management API.
// The operator authenticates with its client certificate, whose Common Name
// and roots the engine's bootstrap names, and verifies the engine against
// the service's serving CA and server name.
package engineclient
