import app from './app';
import config from './config';

const PORT = config.PORT || 5000;

app.listen(PORT, () => console.log(`server running on PORT:: 🚀💥>>> ${PORT}`));
