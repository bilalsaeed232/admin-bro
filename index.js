const AdminBro = require("admin-bro");
const mongoose = require("mongoose");
const AdminBroMongoose = require("@admin-bro/mongoose");
const { buildAuthenticatedRouter } = require("@admin-bro/koa");
const passwordFeature = require("@admin-bro/passwords");
const argon2 = require("argon2");

const Koa = require("koa");
const app = new Koa();
app.keys = ["super-secret1", "super-secret2"];
AdminBro.registerAdapter(AdminBroMongoose);

const User = mongoose.model("User", {
  email: { type: String, required: true },
  encryptedPassword: { type: String, required: true },
});

const run = async () => {
  await mongoose.connect("mongodb://localhost:27017/test", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  if (!(await User.findOne({ email: "admin@example.com" }))) {
    await User.create({
      email: "admin@example.com",
      encryptedPassword: await argon2.hash("password"),
    });
  }

  const adminBro = new AdminBro({
    resources: [
      {
        resource: User,
        options: {
          properties: { encryptedPassword: { isVisible: true } },
        },
        features: [
          passwordFeature({
            properties: { encryptedPassword: "encryptedPassword" },
            hash: argon2.hash,
          }),
        ],
      },
    ],
    rootPath: "/admin",
  });

  adminBro.watch();

  const router = buildAuthenticatedRouter(adminBro, app, {
    authenticate: async (email, password) => {
      const user = email && (await User.findOne({ email }));
      if (
        password &&
        user &&
        (await argon2.verify(user.encryptedPassword, password))
      ) {
        return user.toJSON();
      }
      return null;
    },
  });

  app.use(router.routes()).use(router.allowedMethods());

  app.listen(3000, () =>
    console.log("AdminBro running under localhost:3000/admin")
  );
};

run();
