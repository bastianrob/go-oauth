package mongorepo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/bastianrob/go-oauth/model"
	"github.com/bastianrob/go-oauth/repo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type credentialRepo struct {
	db          *mongo.Database
	credentials *mongo.Collection
}

func (r *credentialRepo) Count(ctx context.Context, email string) (int64, error) {
	findByEmail := bson.M{"email": email}
	return r.credentials.CountDocuments(ctx, findByEmail)
}

//Get 1 credential based on email address
//Returns ErrNotFound if not found
func (r *credentialRepo) Get(ctx context.Context, email string) (model.Credential, error) {
	cred := model.Credential{}
	findByEmail := bson.M{"email": email}
	res := r.credentials.FindOne(ctx, findByEmail)
	err := res.Decode(&cred)
	if err == mongo.ErrNoDocuments {
		return cred, repo.ErrNotFound
	}

	return cred, err
}

//Create a new credential
func (r *credentialRepo) Create(ctx context.Context, cred model.Credential) error {
	cred.ID = primitive.NewObjectIDFromTimestamp(time.Now()).Hex()
	_, err := r.credentials.InsertOne(ctx, cred)
	return err
}
